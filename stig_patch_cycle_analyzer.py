"""
stig_patch_cycle_analyzer.py

Version: 1.0.0
Author: Jamison Lewis
License: MIT
Copyright (c) 2026, Saorsa Industries

Description:
Standalone utility for parsing DISA STIG XCCDF manuals, generating
normalized datasets, patch-cycle deltas, and executive summary reports.

Designed for offline, air-gapped, and regulated environments.
"""

__author__ = "Jamison Lewis"
__version__ = "1.0.0"
__license__ = "MIT"


import zipfile
import re
import csv
import xml.etree.ElementTree as ET
import argparse
import json
import hashlib

from pathlib import Path
from datetime import datetime, UTC
from collections import Counter


SCRIPT_NAME = "stig_patch_cycle_analyzer.py"


# Maps severity name to its weight
severity_dict = {
    "HIGH": 10.00,
    "MEDIUM": 4.00,
    "LOW": 1.00
}


# contains the targeted namespaces within the STIG manuals
ns = {
    "default": "http://checklists.nist.gov/xccdf/1.1"
}


"""
Catalog Format:
STIG_MANUAL_NAME:
    |
    |
    -->"FILE_NAME"
    -->"FULL_PATH"
    -->"STIG_VERSION"
    -->"STIG_REVISION"
    -->"BENCHMARK_DATE"
    -->"TOTAL_VULNS"
    -->VULN_IDs:
            |
            |
            -->"VULN_ID"
            -->"Other_Vuln_meta_data"
"""
stig_manual_catalog = {}


#==================== Versioning Helpers ========================#

def _utc_ts() -> str:
    # stable timestamp for metadata (UTC, ISO-8601, seconds)
    return datetime.now(UTC).replace(microsecond=0).isoformat() + "Z"


def _sha256_file(path: Path) -> str:
    """
    Compute SHA-256 for a file (streamed).
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_csv_preamble(fp, *, run_ts_utc: str, run_id: str | None = None) -> None:
    # write comment lines to csv
    fp.write(f"# tool: {SCRIPT_NAME}\n")
    fp.write(f"# version: {__version__}\n")
    fp.write(f"# run_ts_utc: {run_ts_utc}\n")
    if run_id:
        fp.write(f"# run_id: {run_id}\n")

def print_version_banner() -> None:
    print(f"{SCRIPT_NAME} v{__version__}")

#================== Versioning Helpers END ======================#


def write_checksums(run_dir: Path, paths: list[Path]) -> Path:
    """
    Write CHECKSUMS.sha256 into run_dir for the provided paths.
    Format matches common sha256sum output:
        <hex>  <filename>
    """
    out = run_dir / "CHECKSUMS.sha256"
    lines: list[str] = []

    for p in paths:
        if p and p.exists() and p.is_file():
            digest = _sha256_file(p)
            # store relative filename so the file remains portable with the run folder
            rel = p.resolve().relative_to(run_dir.resolve()) if str(p.resolve()).startswith(str(run_dir.resolve())) else p.name
            lines.append(f"{digest}  {rel}")

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def ensure_unique_run_dir(base_dir: Path) -> Path:
    """
    If base_dir exists, append _2, _3, ... until a unique directory is found.
    Returns a Path that does not yet exist.
    """
    if not base_dir.exists():
        return base_dir

    parent = base_dir.parent
    stem = base_dir.name

    i = 2
    while True:
        candidate = parent / f"{stem}_{i}"
        if not candidate.exists():
            return candidate
        i += 1



def init_run_outputs(run_dir: Path, *, run_id: str | None = None) -> tuple[Path, Path, str]:
    """
    Create a run directory and initialize output CSVs inside it.
    Returns: (overview_csv_path, specifications_csv_path, run_ts_utc)
    """
    run_dir.mkdir(parents=True, exist_ok=True)

    run_ts_utc = _utc_ts()

    manuals_overview = run_dir / "STIG_MANUALS_OVERVIEW.csv"
    manual_specifications = run_dir / "STIG_MANUALS_SPECIFICATIONS.csv"

    # Write CSV preamble + header (keep your schema unchanged)
    with open(manuals_overview, "w", encoding="utf-8", newline="") as fp:
        _write_csv_preamble(fp, run_ts_utc=run_ts_utc, run_id=run_id)
        fp.write("STIG_NAME,STIG_ID,FILE_NAME,FULL_PATH,STIG_VERSION,STIG_REVISION,BENCHMARK_DATE,TOTAL_VULNS,NUM_CAT1,NUM_CAT2,NUM_CAT3\n")

    with open(manual_specifications, "w", encoding="utf-8", newline="") as fp:
        _write_csv_preamble(fp, run_ts_utc=run_ts_utc, run_id=run_id)
        fp.write("STIG_NAME,STIG_ID,FILE_NAME,FULL_PATH,STIG_VERSION,STIG_REVISION,BENCHMARK_DATE,VULN_ID,RULE_ID,LEGACY_IDS,CCI_REFS,SEVERITY,WEIGHT,RULE_TITLE\n")

    return manuals_overview, manual_specifications, run_ts_utc



def catalog_manager(catalog_key:str) -> int:
    """
    This function manages the addition of manuals to the parsing
    catalog. It ensures no duplicates are added to the dictionary
    containing all data pertaining to STIG manuals.
    Each manual name is a key inside the catalog
    """

    stig_manuals = list(stig_manual_catalog.keys())

    # the manual in question is a duplicate file
    # return 1 signifying an issuue with the addition 
    # of the manual into the catalog 
    if catalog_key in stig_manuals:
        #print(f"DUPLICATE: {catalog_key}")
        return 1
    else:
        stig_manual_catalog[catalog_key] = {}
        return 0
    

def stig_manual_filter(zf:zipfile.ZipFile)->list[Path]:
    """
    Given the ZipFile object, search for all files within the .zip
    and filter them based on the substrings common in DISA STIG manuals
    Returns: list containing paths to thhe STIG manuals within the .zip
    """

    manual_patterns = ["*_Manual-xccdf.xml", "*_Manual_xccdf.xml", "*_STIG.xml"] # patterns indicating a file is a STIG manual

    items = zipfile.Path(zf).rglob("*") # get all items within the .zip
    
    # filter the items in the list 
    # leaving only STIG Manuals
    manuals = [
        file for file in items
        if any(file.match(pattern) for pattern in manual_patterns) and file.is_file()
    ]
    
    return manuals


def write_to_file(manuals_overview: Path, manual_specifications: Path) -> None:
    with open(manuals_overview, 'a', newline='', encoding="utf-8") as fp:
        writer = csv.writer(fp)

        for manual in stig_manual_catalog:
            manual_dict = stig_manual_catalog[manual]

            accounted_cols = [
                "STIG_NAME", "STIG_ID", "FILE_NAME", "FULL_PATH",
                "STIG_VERSION", "STIG_REVISION", "BENCHMARK_DATE",
                "TOTAL_VULNS", "NUM_CAT1", "NUM_CAT2", "NUM_CAT3"
            ]

            row_data = [
                manual_dict["STIG_NAME"],
                manual_dict["STIG_ID"],
                manual_dict["FILE_NAME"],
                manual_dict["FULL_PATH"],
                manual_dict["STIG_VERSION"],
                manual_dict["STIG_REVISION"],
                manual_dict["BENCHMARK_DATE"],
                manual_dict["TOTAL_VULNS"],
                manual_dict["NUM_CAT1"],
                manual_dict["NUM_CAT2"],
                manual_dict["NUM_CAT3"],
            ]
            writer.writerow(row_data)

    with open(manual_specifications, 'a', newline='', encoding="utf-8") as fp2:
        writer2 = csv.writer(fp2)

        for manual in stig_manual_catalog:
            manual_dict = stig_manual_catalog[manual]

            accounted_cols = [
                "STIG_NAME", "STIG_ID", "FILE_NAME", "FULL_PATH",
                "STIG_VERSION", "STIG_REVISION", "BENCHMARK_DATE",
                "TOTAL_VULNS", "NUM_CAT1", "NUM_CAT2", "NUM_CAT3"
            ]
            targeted_keys = sorted(set(manual_dict.keys()) - set(accounted_cols))

            for vid in targeted_keys:
                row_data2 = [
                    manual_dict["STIG_NAME"],
                    manual_dict["STIG_ID"],
                    manual_dict["FILE_NAME"],
                    manual_dict["FULL_PATH"],
                    manual_dict["STIG_VERSION"],
                    manual_dict["STIG_REVISION"],
                    manual_dict["BENCHMARK_DATE"],
                    manual_dict[vid]["VULN_ID"],
                    manual_dict[vid]["RULE_ID"],
                    manual_dict[vid]["LEGACY_IDS"],
                    manual_dict[vid]["CCI_REFS"],
                    manual_dict[vid]["SEVERITY"],
                    manual_dict[vid]["WEIGHT"],
                    manual_dict[vid]["RULE_TITLE"],
                ]
                writer2.writerow(row_data2)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    """Write JSON Lines (one object per line)."""
    with open(path, "w", encoding="utf-8") as fp:
        for r in rows:
            fp.write(json.dumps(r, ensure_ascii=False) + "\n")


def write_json(path: Path, obj) -> None:
    """Write pretty JSON (single file)."""
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def read_csv_as_dicts(path: Path) -> list[dict]:
    """
    Read CSV into a list of dicts.
    Skips leading comment lines starting with '#'.
    """
    with open(path, "r", newline="", encoding="utf-8") as f:
        # Skip comment/preamble lines
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                f.seek(pos)
                break
            if not line.lstrip().startswith("#"):
                f.seek(pos)
                break

        reader = csv.DictReader(f)
        return [dict(r) for r in reader]


def parse_stig_manuals(zf:zipfile.ZipFile, manual_paths:list[Path], parent_path:str = None, quiet:bool = True):
    """
    Given the ZipFile object, loop through all STIG manuals within the 
    .zip, open them, and parse the xml tree
    """

    manual_paths = [x for x in manual_paths if 'Supplemental' not in str(x)] # remove STIG manuals from supplemental repositories

    # loop all paths to STIG manuals
    for manual_path in manual_paths:
        
        full_path = str(manual_path) # keep the original relative path
        
        manual_path = Path(full_path).as_posix().split('/')[-2:] # split manual path and grab immediate child path

        catalog_key = manual_path[-1].upper() # used to record the processed STIG manuals

        num_cat1 = 0
        num_cat2 = 0
        num_cat3 = 0

        # if the return == 1
        # do not process the manual, it is a duplicate. skip it
        if(catalog_manager(catalog_key)):
            continue
        else:
            # append the parent path to nested .zip files
            if(parent_path != None):
                full_path =  parent_path + full_path

            # modify path string formatting
            full_path = full_path.replace('/', '\\')

            if not quiet:
                print(full_path)

            manual_path = '/'.join(manual_path) # create path within context of working directory/.zip

            # Add file name and full path to dictionary
            stig_manual_catalog[catalog_key]["FILE_NAME"] = catalog_key
            stig_manual_catalog[catalog_key]["FULL_PATH"] = full_path


            manual = zf.open(manual_path) # open the manual

            tree = ET.parse(manual) # parse the .xml STIG library
            root = tree.getroot() # get root tag of STIG manual

            stig_id = root.attrib['id'].upper()# get the STIG_ID
            stig_manual_catalog[catalog_key]["STIG_ID"] = stig_id


            title_el = root.find('default:title', ns)
            raw_title = (title_el.text or "") if title_el is not None else ""
            tech_name = (raw_title.replace('Security Technical Implementation Guide', '').replace('Security Requirements Guide', '').replace('STIG', '').upper().strip()) or "NONE" # get the technology name
            stig_manual_catalog[catalog_key]["STIG_NAME"] = tech_name


            stig_version = root.find("default:version", ns).text # get the STIG version
            stig_manual_catalog[catalog_key]["STIG_VERSION"] = stig_version
            
            # Used to find benchmark date and STIG revision number
            release_tag = root.find('default:plain-text[@id="release-info"]', ns)
            res = (release_tag.text or "") if release_tag is not None else ""
            if not res.strip():
                raise RuntimeError(f"Missing release-info in {catalog_key}")


            ## Get benchmark date (support multiple formats found in release-info) ##
            bench_date = None

            # Format A: "28 Oct 2025" or "28 October 2025"
            m = re.search(r"(\d{1,2}\s(?:Jan|January|Feb|February|Mar|March|Apr|April|May|Jun|June|Jul|July|Aug|August|Sep|Sept|September|Oct|October|Nov|November|Dec|December)\s\d{4})", res)
            if m:
                bench_date = m.group(1)

            # Format B: "28-Oct-25" or "28-Oct-2025"
            if not bench_date:
                m = re.search(r"(\d{1,2}-[A-Za-z]{3}-\d{2,4})", res)
                if m:
                    bench_date = m.group(1)

            if not bench_date:
                raise RuntimeError(f"Could not parse BENCHMARK_DATE from release-info for {catalog_key}")
            stig_manual_catalog[catalog_key]["BENCHMARK_DATE"] = bench_date.strip().upper()


            # Get STIG revision number
            stig_revision = re.search(r'(Release:\s\d+)', res).group()
            stig_revision = re.search(r'(\d+)', res).group()
            stig_manual_catalog[catalog_key]["STIG_REVISION"] = stig_revision

            # Get all vuln group tags
            vuln_tags = root.findall('default:Group', ns)

            # Get number of vulns checked in the STIG
            num_vulns = len(vuln_tags)
            stig_manual_catalog[catalog_key]["TOTAL_VULNS"] = num_vulns


            # traverse vulnerabilities and gather relevant meta-data
            for vuln in vuln_tags:
                vuln_dict = {} # holds data pertaining to vulnerability

                # get the vulnerability ID
                vuln_id = vuln.get("id")
                vuln_dict["VULN_ID"] = vuln_id 

                #Get the rule tag
                rule_tag = vuln.find("default:Rule",ns)

                # Used to get the vulnerability rule_id, weight, and severity
                rule_data = rule_tag.attrib
                
                vuln_dict["RULE_ID"] = rule_data["id"].upper() # Get rule ID
                vuln_dict["SEVERITY"] = rule_data["severity"].upper() # Get severity classification
                vuln_dict["WEIGHT"] = severity_dict[rule_data["severity"].upper()] # get severity weight

                # Update the counts of cat1, cat2, and cat3
                if(vuln_dict["SEVERITY"] == "HIGH"):
                    num_cat1+=1
                elif(vuln_dict["SEVERITY"] == "MEDIUM"):
                    num_cat2+=1
                elif(vuln_dict["SEVERITY"] == "LOW"):
                    num_cat3+=1


                #Get the VID Description
                title_el = rule_tag.find("default:title", ns)
                vid_title = (title_el.text or "").strip() if title_el is not None else ""
                vuln_dict["RULE_TITLE"] = vid_title if vid_title else "NONE"


                # Get the legacy IDs and the relevant CCIs
                ident_tags = rule_tag.findall("default:ident", ns)
                legacy_ids = [] # Holds the legacy Ids
                ccis = []   #holds the CCIs pertaining to Vuln-id
                for ident in ident_tags:
                    sys_attr_data = ident.get("system").upper() # The "system" attribute contains a url identifier

                    # If the URI contains "Legacy", means it is a legacy ID
                    if("LEGACY" in sys_attr_data):
                        legacy_ids.append(ident.text.upper())

                    # If the URI contains "CCI", means it contains a CCI
                    elif("CCI" in sys_attr_data):
                        ccis.append(ident.text.upper())

                # transform legacy id list into string
                if (len(legacy_ids) > 0):
                    vuln_dict["LEGACY_IDS"] = str(legacy_ids).replace('[','').replace(']','')
                else:
                    vuln_dict["LEGACY_IDS"] = "NONE"

                # transform CCI refs list into string
                if (len(ccis) > 0):
                    vuln_dict["CCI_REFS"] = str(ccis).replace('[','').replace(']','')
                else:
                    vuln_dict["CCI_REFS"] = "NONE"


                stig_manual_catalog[catalog_key][vuln_id] = vuln_dict # vulnerability meta-data to STIG dict

        stig_manual_catalog[catalog_key]["NUM_CAT1"] = num_cat1 # add total number of Cat 1's to STIG dict
        stig_manual_catalog[catalog_key]["NUM_CAT2"] = num_cat2 # add total number of Cat 2's to STIG dict
        stig_manual_catalog[catalog_key]["NUM_CAT3"] = num_cat3 # add total number of Cat 3's to STIG dict

    return


def stig_library_parse(stig_lib_path_obj:Path, exclude_compiled_library:bool, manuals_overview:Path, manual_specifications:Path, quiet:bool = True) -> None:
    """
    Crawl the targeted STIG library looking for all STIG manuals 
    """
    stig_manual_catalog.clear() # clear global dict in case of batch runs in same Python environment

    zip_list = list(stig_lib_path_obj.glob("*.zip", case_sensitive=True)) # create list of all parent .zip files within the STIG Library

    # traverse all 1st level .zips within the STIG Library
    for zip_file in zip_list:

        if exclude_compiled_library:
            # Skip the compiled library
            compiled_lib_substring = ['CUI_SRG-STIG_Library', 'U_SRG-STIG_Library']
            if any(sub in str(zip_file) for sub in compiled_lib_substring):
                #print("LIBRARY COMPILATION")
                continue

        if not quiet:
            print(zip_file) # print the zip file path


        # open .zip file
        with zipfile.ZipFile(zip_file,'r') as zf:

            # Use case 1: check for 1st level nested .zip files containing STIG Manuals
            if (any('.zip' in item for item in zf.namelist())):
                # if nested .zips, loop items 
                for item in zf.infolist():
                    # compare for .zip files within the parent .zip
                    if(item.filename.__contains__(".zip")):

                        parent_path = str(zip_file)+ '\\' # save the parent path of nested .zip

                        #open the nested .zip
                        with zipfile.ZipFile(zf.open(item.filename, 'r')) as zf2:

                            # filter Rglob output to only include STIG manuals 
                            manuals = stig_manual_filter(zf2)
                            parse_stig_manuals(zf2, manuals, parent_path, quiet=quiet)
                            
            # Default Use case: no nested .zip files containing STIG Manuals              
            else:
                manuals = stig_manual_filter(zf)
                parse_stig_manuals(zf, manuals, quiet=quiet)
        
        if not quiet:
            print('\n')
    
    if not quiet:
        print(f"STIG Manual Count: {len(stig_manual_catalog.keys())}")

    #write to file
    write_to_file(manuals_overview, manual_specifications)
    return


def write_latest_run_pointer(base_out_dir: Path, run_dir: Path) -> None:
    """
    Write a pointer file that always contains the absolute path of the latest run folder.
    """
    base_out_dir.mkdir(parents=True, exist_ok=True)
    latest_file = base_out_dir / "LATEST_RUN.txt"
    latest_file.write_text(str(run_dir.resolve()) + "\n", encoding="utf-8")


def write_run_summary(
    run_dir:Path, *, target:Path, exclude_compiled_library:bool, quiet:bool, manuals_overview:Path, manual_specifications:Path, \
          stig_manual_count:int, delta_ran:bool = False, delta_out_dir:Path|None = None, delta_overview:Path|None = None, delta_vulns:Path|None = None) -> None:
    """
    Write RUN_SUMMARY.txt into the run folder
    """
    lines: list[str] = []
    lines.append(f"SCRIPT_NAME: {SCRIPT_NAME}")
    lines.append(f"SCRIPT_VERSION: {__version__}")
    lines.append(f"SCRIPT_LICENSE: {__license__}")
    lines.append(f"RUN_TIMESTAMP: {datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"RUN_DIR: {run_dir.resolve()}")
    lines.append(f"TARGET: {target.resolve()}")
    lines.append(f"EXCLUDE_COMPILED_LIBRARY: {exclude_compiled_library}")
    lines.append(f"QUIET: {quiet}")
    lines.append(f"STIG_MANUAL_COUNT: {stig_manual_count}")

    lines.append(f"OVERVIEW_CSV: {manuals_overview.resolve()}")
    lines.append(f"SPECIFICATIONS_CSV: {manual_specifications.resolve()}")

    lines.append(f"DELTA_RAN: {delta_ran}")
    if delta_ran:
        lines.append(f"DELTA_OUT_DIR: {delta_out_dir.resolve() if delta_out_dir else ''}")
        lines.append(f"DELTA_OVERVIEW_CSV: {delta_overview.resolve() if delta_overview else ''}")
        lines.append(f"DELTA_VULNS_CSV: {delta_vulns.resolve() if delta_vulns else 'SKIPPED/NOT_GENERATED'}")

    (run_dir / "RUN_SUMMARY.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


#======================= Delta Mode ==================================#
def _norm(s:str)-> str:
    return (s or "").strip().upper().replace(" ", "_")

def _read_csv(path:Path)-> tuple[list[str], list[dict]]:
    """
    Read CSV into normalized dict rows.
    Skips leading comment/preamble lines starting with '#'

    Returns: (normalized_fieldnames, rows)
    """
    with open(path, "r", newline="", encoding="utf-8") as fp:
        ## Skip comment preamble ##
        while True:
            pos = fp.tell()
            line = fp.readline()
            if not line:
                fp.seek(pos)
                break
            if not line.lstrip().startswith("#"):
                fp.seek(pos)
                break

        reader = csv.DictReader(fp)
        fieldnames = [(_norm(h) if h else "") for h in (reader.fieldnames or [])] # list of normalized column names in the csv
        rows:list[dict] = [] # each index is a dictionary containing data for reach row (keys are column_name, values are values within a particular row cell)
        for r in reader:
            nr = {} # normalized row ({"column_name": "value_in_row"})
            for k, v in (r or {}).items():
                nk = _norm(k) # normalize the key/column name 
                nv = v.strip() if isinstance(v, str) else v # normalize the value
                nr[nk] = nv
            rows.append(nr)
        return fieldnames, rows 


def _get(row:dict, *keys:str, default:str = "")-> str:
    """
    Retrive data from row using normalized column name 
    row: dictionary of {k = normalized column name: v = column value in row}
    """
    for k in keys:
        nk = _norm(k)
        if nk in row and row[nk] not in (None, ""):
            return str(row[nk]).strip() # retrun cell value for given key/column name
    return default # if no key is given


def _safe_int(x: str) -> int:
    try:
        return int(str(x).strip())
    except Exception:
        return 0


def _stig_key(row:dict, *, mode:str = "id")-> str:
    """
    mode:
        - "id" : STIG_ID only
        - "id_version_revision" -> {STIG_ID}::V{STIG_VERSION}::R{STIG_REVISION}
    Returns STIG identifier based on mode
    """
    stig_id = _get(row, "STIG_ID") # get STIG ID of the current row
    if mode == "id_version_revision":
        v = _get(row, "STIG_VERSION") # get STIG version
        r = _get(row, "STIG_REVISION") # get STIG revision
        return f"{stig_id}::V{v}::R{r}"
    return stig_id


def _vuln_key(row:dict, *, mode:str = "stig_vuln_rule")-> str:
    """
    mode:
        - "stig_vuln": {STIG_ID}::{VULN_ID}
        - "stig_vuln_rule": {STIG_ID}::{VULN_ID}::{RULE_ID} 
    Return vuln identifier based on mode
    """
    stig_id = _get(row, "STIG_ID")
    vuln_id = _get(row, "VULN_ID")
    if mode == "stig_vuln":
        return f"{stig_id}::{vuln_id}"
    rule_id = _get(row, "RULE_ID")
    return f"{stig_id}::{vuln_id}::{rule_id}"


def _collapse_ws(s: str) -> str:
    """
    normalizes tabs and multiple spaces
    """
    return re.sub(r"\s+", " ", (s or "").replace("\u00A0", " ").strip())


def _canon_benchmark_date(s: str) -> str:
    """
    Canonicalize BENCHMARK_DATE into YYYY-MM-DD when possible.

    Handles:
      - 28-Oct-25
      - 28-Oct-2025
      - 28 Oct 2025
      - 28 October 2025
    """
    raw = _collapse_ws(s)

    # Normalize common separators: keep hyphens if present, collapse spaces
    raw2 = raw.replace("/", "-")
    raw2 = _collapse_ws(raw2)

    # Try multiple formats (case-insensitive month)
    candidates = [
        ("%d-%b-%y", raw2),   # 28-Oct-25
        ("%d-%b-%Y", raw2),   # 28-Oct-2025
        ("%d %b %Y", raw2),   # 28 Oct 2025
        ("%d %B %Y", raw2),   # 28 October 2025
    ]

    for fmt, val in candidates:
        try:
            # datetime.strptime is case-insensitive for %b/%B
            # normalize to Title case to be sure
            dt = datetime.strptime(val.title(), fmt)
            return dt.strftime("%Y-%m-%d")
        except Exception:
            continue

    # If parsing fails, return stable normalized string for comparison
    return _collapse_ws(raw2).upper()


def _canon_field(field: str, value: str) -> str:
    """
    Canonicalize fields for delta comparisons
    """

    f = _norm(field)
    v = _collapse_ws(value)

    if f == "BENCHMARK_DATE":
        return _canon_benchmark_date(v)

    if f in {"TOTAL_VULNS", "NUM_CAT1", "NUM_CAT2", "NUM_CAT3"}:
        return str(_safe_int(v))
    
    if f == "WEIGHT":
        try:
            return f"{float(v):.2f}"
        except:
            return _collapse_ws(v).upper()

    # Default: compare normalized whitespace and case
    return _collapse_ws(v).upper()


def _validate_required_columns(csv_path:Path, required_cols:set[str], *, label:str)-> bool:
    """
    Ensures required columns are contained in the target csv

    Returns:
        - True: all required columns exist
        - False: required columns missing
    """
    fieldnames, _ = _read_csv(csv_path) # get normalized csv columns
    got = set(fieldnames) # ensure fieldnames are unique
    req = {_norm(c) for c in required_cols} # ensure same tranformation performed on required cols list
    missing = sorted(req - got)
    if missing:
        print(f"[WARN] {label} missing required columns in {csv_path}: {missing}")
        return False
    return True


def _liststr_to_set(value:str)-> set[str]:
    """
    Convert a list string into a normalized set of tokens
    - split on comma
    - strip whitespace
    - strip surrounding quotes
    - drop empty tokens and "NONE"
    - upercase tokens
    """
    s = _collapse_ws(value)
    if not s:
        return set()
    
    if s.strip().upper() == "NONE":
        return set()
    
    out:set[str] = set()
    for tok in s.split(","):
        t = tok.replace("'", "").replace('"', '').strip().upper()
        if not t or t == "NONE":
            continue
        out.add(t)

    return out


def generate_delta_outputs(*, prev_overview:Path, curr_overview:Path, prev_specs:Path|None, curr_specs:Path|None, delta_out_dir:Path, \
                            stig_key_mode:str = "id", vuln_key_mode:str = "stig_vuln_rule")-> tuple[Path, Path|None]:
    """
    Produces:
        - DELTA_OVERVIEW.csv
        - DELTA_VULNS.csv (if specs are provided and valid)
    
    Returns: (delta_overview_path, delta_vulns_path_or_none)
    """
    delta_out_dir.mkdir(parents=True, exist_ok=True)

    #
    # STIG Manuals Overview delta #
    #
    _, prev_rows = _read_csv(prev_overview) # parse previous STIG overview csv
    _, curr_rows = _read_csv(curr_overview) # parse current STIG overview csv

    prev_map = {_stig_key(r, mode=stig_key_mode): r for r in prev_rows if _stig_key(r, mode=stig_key_mode)} # {STIG_KEY (STIG_ID or id_version_revision): {column_name: value}}
    curr_map = {_stig_key(r, mode=stig_key_mode): r for r in curr_rows if _stig_key(r, mode=stig_key_mode)}

    prev_keys = set(prev_map.keys()) # create sequence of unique STIG_KEYs found in previous csv
    curr_keys = set(curr_map.keys()) # create sequence of unique STIG_KEYs found in current csv

    added = sorted(curr_keys - prev_keys) # STIG_KEYs in current but not in previous
    removed = sorted(prev_keys - curr_keys) # STIG_KEYS in previous but not in current
    common = sorted(prev_keys & curr_keys) # STIG_KEYS in both current and previous

    delta_overview_path = delta_out_dir / "DELTA_OVERVIEW.csv"

    # Fields to detect changes on (for "FIELDS_CHANGED" column)
    compare_fields = ["STIG_NAME", "STIG_VERSION", "STIG_REVISION", "BENCHMARK_DATE", "TOTAL_VULNS", "NUM_CAT1", "NUM_CAT2", "NUM_CAT3",]

    # build delta overview file
    with open(delta_overview_path, "w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp)
        w.writerow([
            "CHANGE_TYPE",
            "STIG_KEY",
            "STIG_ID",
            "STIG_NAME",
            "OLD_VERSION",
            "OLD_REVISION",
            "NEW_VERSION",
            "NEW_REVISION",
            "OLD_BENCHMARK_DATE",
            "NEW_BENCHMARK_DATE",
            "OLD_TOTAL_VULNS",
            "NEW_TOTAL_VULNS",
            "OLD_NUM_CAT1",
            "NEW_NUM_CAT1",
            "OLD_NUM_CAT2",
            "NEW_NUM_CAT2",
            "OLD_NUM_CAT3",
            "NEW_NUM_CAT3",
            "FIELDS_CHANGED",
        ])

        def _ov_summary(r:dict)-> dict:
            return {
                "STIG_ID": _get(r, "STIG_ID"),
                "STIG_NAME": _get(r, "STIG_NAME"),
                "STIG_VERSION": _get(r, "STIG_VERSION"),
                "STIG_REVISION": _get(r, "STIG_REVISION"),
                "BENCHMARK_DATE": _canon_benchmark_date(_get(r, "BENCHMARK_DATE")),
                "TOTAL_VULNS": _safe_int(_get(r, "TOTAL_VULNS")),
                "NUM_CAT1": _safe_int(_get(r, "NUM_CAT1")),
                "NUM_CAT2": _safe_int(_get(r, "NUM_CAT2")),
                "NUM_CAT3": _safe_int(_get(r, "NUM_CAT3")),
            }
        
        # add rows for added STIG_KEY data to delta overview file
        for k in added:
            n = _ov_summary(curr_map[k]) # dictionary of column_name:value in current STIG_OVERVIEW that was added from previous
            w.writerow([
                "ADDED", k, n["STIG_ID"], n["STIG_NAME"], "", "", n["STIG_VERSION"], n["STIG_REVISION"], "", n["BENCHMARK_DATE"], "", n["TOTAL_VULNS"], "", n["NUM_CAT1"], 
                "", n["NUM_CAT2"], "", n["NUM_CAT3"], "",
            ])

        # add rows for removed STIG_KEY data to delta overview file
        for k in removed:
            o = _ov_summary(prev_map[k]) # dictionary of column_name:value in previous STIG_OVERVIEW that was removed from current
            w.writerow([
                "REMOVED", k, o["STIG_ID"], o["STIG_NAME"], o["STIG_VERSION"], o["STIG_REVISION"],"", "", o["BENCHMARK_DATE"], "", o["TOTAL_VULNS"], "", o["NUM_CAT1"], 
                "", o["NUM_CAT2"], "", o["NUM_CAT3"], "", "",
            ])


        # Get STIG_Keys that are in both current and previous, determine if any values have changed and write them to delta overview file
        for k in common:
            old = prev_map[k] # dictionary containing row data
            new = curr_map[k]

            # find targeted field values that have changed from previous to current for a given STIG_KEY
            changed = []
            for f in compare_fields:
                old_v = _canon_field(f, _get(old, f))
                new_v = _canon_field(f, _get(new, f))

                if old_v != new_v:
                    changed.append(f)
            
            if not changed:
                continue

            o = _ov_summary(old)
            n = _ov_summary(new)

            w.writerow([
                "CHANGED", k, n["STIG_ID"] or o["STIG_ID"], n["STIG_NAME"] or o["STIG_NAME"], o["STIG_VERSION"], o["STIG_REVISION"], n["STIG_VERSION"], n["STIG_REVISION"],
                o["BENCHMARK_DATE"], n["BENCHMARK_DATE"], o["TOTAL_VULNS"], n["TOTAL_VULNS"], o["NUM_CAT1"], n["NUM_CAT1"], o["NUM_CAT2"], n["NUM_CAT2"], o["NUM_CAT3"], n["NUM_CAT3"],
                ";".join(sorted(changed)),
            ])
    
    #
    # STIG vulnerability data delta (optional) # 
    #
    delta_vulns_path:Path|None = None

    if prev_specs and curr_specs:
        required_specs_cols = {
            "STIG_ID", "STIG_NAME", "VULN_ID", "RULE_ID", "SEVERITY", "WEIGHT", "RULE_TITLE", "CCI_REFS", "LEGACY_IDS"
        }

        ok_prev = _validate_required_columns(prev_specs, required_specs_cols, label="Previous specs CSV") # ensure required columns exist in previous specifications csv
        ok_curr = _validate_required_columns(curr_specs, required_specs_cols, label="Current specs CSV") # ensure required columns exist in current specifications csv

        if ok_prev and ok_curr:
            _, prev_srows = _read_csv(prev_specs) # parse previous STIG specifications csv
            _, curr_srows = _read_csv(curr_specs) # parse current STIG specifications csv

            prev_v = {_vuln_key(r, mode=vuln_key_mode): r for r in prev_srows if _vuln_key(r, mode=vuln_key_mode)} # {VULN_KEY: {column_name: value}}
            curr_v = {_vuln_key(r, mode=vuln_key_mode): r for r in curr_srows if _vuln_key(r, mode=vuln_key_mode)}

            prev_vk = set(prev_v.keys()) # create sequence of unique VULN_KEYs found in previous csv
            curr_vk = set(curr_v.keys()) # create sequence of unique VULN_KEYs found in current csv

            v_added = sorted(curr_vk - prev_vk) # VULN_KEYs in current but not in previous
            v_removed = sorted(prev_vk - curr_vk) # VULN_KEYs in previous but not in current
            v_common = sorted(prev_vk & curr_vk) # VULN_KEYs in both previous and current

            delta_vulns_path = delta_out_dir / "DELTA_VULNS.csv" # absolute path to vulnerability delta file
            vuln_compare_fields = ["SEVERITY", "WEIGHT", "RULE_TITLE", "CCI_REFS", "LEGACY_IDS"] # target fields to compare

            # write header to vulnerability delta file
            with open(delta_vulns_path, "w", newline="", encoding="utf-8") as fp:
                w = csv.writer(fp)
                w.writerow([
                    "CHANGE_TYPE",
                    "VULN_KEY",
                    "STIG_ID",
                    "STIG_NAME",
                    "VULN_ID",
                    "RULE_ID",
                    "OLD_SEVERITY",
                    "NEW_SEVERITY",
                    "OLD_WEIGHT",
                    "NEW_WEIGHT",
                    "OLD_RULE_TITLE",
                    "NEW_RULE_TITLE",
                    "OLD_CCI_REFS",
                    "NEW_CCI_REFS",
                    "OLD_LEGACY_IDS",
                    "NEW_LEGACY_IDS",
                    "FIELDS_CHANGED",
                ])

                def _vs(r:dict)-> dict:
                    return {
                        "STIG_ID": _get(r, "STIG_ID"),
                        "STIG_NAME": _get(r, "STIG_NAME"),
                        "VULN_ID": _get(r, "VULN_ID"),
                        "RULE_ID": _get(r, "RULE_ID"),
                        "SEVERITY": _get(r, "SEVERITY"),
                        "WEIGHT": _get(r, "WEIGHT"),
                        "RULE_TITLE": _get(r, "RULE_TITLE"),
                        "CCI_REFS": _get(r, "CCI_REFS"),
                        "LEGACY_IDS": _get(r, "LEGACY_IDS"),
                    }
                

                # add rows for added VULN_KEY data from prev to curr to delta specs file
                for k in v_added:
                    n = _vs(curr_v[k]) # dict of values for a given VULN_KEY in current specification csv
                    w.writerow(["ADDED", k, n["STIG_ID"], n["STIG_NAME"], n["VULN_ID"], n["RULE_ID"], "", n["SEVERITY"], "", n["WEIGHT"], "", n["RULE_TITLE"], "", n["CCI_REFS"], "", n["LEGACY_IDS"], "",])
                
                # add rows for removed VULN_KEY data from prev to curr to delta specs file
                for k in v_removed:
                    o = _vs(prev_v[k]) # dict of values for a given VULN_KEY in previous specification csv
                    w.writerow(["REMOVED", k, o["STIG_ID"], o["STIG_NAME"], o["VULN_ID"], o["RULE_ID"], o["SEVERITY"], "", o["WEIGHT"], "", o["RULE_TITLE"], "", o["CCI_REFS"], "", o["LEGACY_IDS"], "", "",])

                # Get VULN_Keys data that are in both current and previous, determine if any values have changed and write them to delta specs file
                for k in v_common:
                    old = prev_v[k]
                    new = curr_v[k]

                    # find targeted field values that have changed from previous to current for a given VULN_KEY
                    changed = []
                    for f in vuln_compare_fields: 
                        # LEGACY_IDS and CCI_REFS are lists; using set logic for comparison
                        if f in ["LEGACY_IDS", "CCI_REFS"]:
                            old_set = _liststr_to_set(_get(old, f))
                            new_set = _liststr_to_set(_get(new, f))
                            if old_set != new_set:
                                changed.append(f)
                        else:
                            old_v = _canon_field(f, _get(old, f))
                            new_v = _canon_field(f, _get(new, f))
                            if old_v != new_v:
                                changed.append(f)

                    if not changed:
                        continue

                    o = _vs(old)
                    n = _vs(new)

                    w.writerow([
                        "CHANGED", k, n["STIG_ID"] or o["STIG_ID"], n["STIG_NAME"] or o["STIG_NAME"], n["VULN_ID"] or o["VULN_ID"], n["RULE_ID"] or o["RULE_ID"],
                          o["SEVERITY"], n["SEVERITY"], o["WEIGHT"], n["WEIGHT"], o["RULE_TITLE"], n["RULE_TITLE"], o["CCI_REFS"], n["CCI_REFS"], o["LEGACY_IDS"], n["LEGACY_IDS"], ";".join(sorted(changed)),
                    ])

        else:
            print("[WARN] Skipping vuln delta due to invalid STIG SPECIFICATIONS file column(s)")

    return delta_overview_path, delta_vulns_path


def write_delta_only_summary( delta_out_dir:Path, *, prev_overview:Path, curr_overview:Path, prev_specs:Path|None, curr_specs:Path|None, delta_overview:Path, delta_vulns:Path|None)-> None:
    lines: list[str] = []
    lines.append(f"SCRIPT_NAME: {SCRIPT_NAME}")
    lines.append(f"SCRIPT_VERSION: {__version__}")
    lines.append(f"SCRIPT_LICENSE: {__license__}")
    lines.append(f"RUN_TIMESTAMP: {datetime.now().isoformat(timespec='seconds')}")
    lines.append("MODE: DELTA_ONLY")
    lines.append(f"DELTA_OUT_DIR: {delta_out_dir.resolve()}")
    lines.append(f"PREV_OVERVIEW: {prev_overview.resolve()}")
    lines.append(f"CURR_OVERVIEW: {curr_overview.resolve()}")
    lines.append(f"PREV_SPECS: {prev_specs.resolve() if prev_specs else ''}")
    lines.append(f"CURR_SPECS: {curr_specs.resolve() if curr_specs else ''}")
    lines.append(f"DELTA_OVERVIEW_CSV: {delta_overview.resolve()}")
    lines.append(f"DELTA_VULNS_CSV: {delta_vulns.resolve() if delta_vulns else 'SKIPPED/NOT_GENERATED'}")
    (delta_out_dir / "DELTA_ONLY_SUMMARY.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


#======================= Delta Mode END ==================================#


#===================== Executive Patch-Cycle Summary =====================#

def _read_csv_dicts(path: Path) -> list[dict]:
    """
    Read CSV into a list of dicts.
    Skips leading comment lines starting with '#'.
    """
    with open(path, "r", newline="", encoding="utf-8") as f:
        # Skip comment/preamble lines
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                f.seek(pos)
                break
            if not line.lstrip().startswith("#"):
                f.seek(pos)
                break

        reader = csv.DictReader(f)
        return [dict(r) for r in reader]


def _fmt_counter_lines(c:Counter, *, prefix:str = "  - ", limit:int|None = None) -> list[str]:
    items = c.most_common(limit) if limit else c.most_common()
    out:list[str] = []
    for k, v in items:
        out.append(f"{prefix}{k}: {v}")
    return out


def write_executive_patch_cycle_summary(*, delta_out_dir:Path, prev_overview:Path, curr_overview:Path, prev_specs:Path|None, curr_specs:Path|None, \
                                         delta_overview_csv:Path, delta_vulns_csv:Path|None, top_n:int = 10) -> Path:
    """
    Write an executive patch-cycle summary into the delta output directory.

    Outputs:
      - EXECUTIVE_PATCH_CYCLE_SUMMARY.txt
    """
    delta_out_dir.mkdir(parents=True, exist_ok=True)
    out_path = delta_out_dir / "EXECUTIVE_PATCH_CYCLE_SUMMARY.txt"

    ts = datetime.now().isoformat(timespec="seconds")
    lines: list[str] = []

    #-------- Overview summary --------#
    o_rows = _read_csv_dicts(delta_overview_csv)
    o_change = Counter() # Count change types
    o_fields = Counter() # count fields changed if the change type was of class "CHANGED"
    o_by_stig = Counter()  # impact score per STIG based on count of changed fields

    for row in o_rows:
        ct = (row.get("CHANGE_TYPE") or "").strip().upper() or "UNKNOWN"
        o_change[ct] += 1

        if ct == "CHANGED":
            fc = (row.get("FIELDS_CHANGED") or "").strip()
            fields = [f.strip() for f in fc.split(";") if f.strip()]
            for f in fields:
                o_fields[f] += 1
            stig_name = (row.get("STIG_NAME") or "").strip() or "UNKNOWN_STIG"
            # Impact score = number of changed fields on this STIG row
            o_by_stig[stig_name] += max(1, len(fields))

    #-------- Vuln summary (optional) --------#
    v_change = Counter() # Count change type
    v_by_stig = Counter() # Count vuln by STIG found in delta report
    v_fields = Counter() # count vuln fields affected 

    v_added_sev = Counter() # count num of severity added
    v_removed_sev = Counter() # count num of severity removed

    sev_up = 0 # count num severity increases in delta report
    sev_down = 0 # count num severity decreases in delta report

    if delta_vulns_csv and delta_vulns_csv.exists():
        v_rows = _read_csv_dicts(delta_vulns_csv)

        for row in v_rows:
            ct = (row.get("CHANGE_TYPE") or "").strip().upper() or "UNKNOWN"
            v_change[ct] += 1

            stig_name = (row.get("STIG_NAME") or "").strip() or "UNKNOWN_STIG"
            v_by_stig[stig_name] += 1

            if ct == "CHANGED":
                fc = (row.get("FIELDS_CHANGED") or "").strip()
                fields = [f.strip() for f in fc.split(";") if f.strip()]
                for f in fields:
                    v_fields[f] += 1

                old_sev = (row.get("OLD_SEVERITY") or "").strip().upper()
                new_sev = (row.get("NEW_SEVERITY") or "").strip().upper()

                # Severity direction (HIGH > MEDIUM > LOW)
                sev_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
                if old_sev in sev_rank and new_sev in sev_rank:
                    if sev_rank[new_sev] > sev_rank[old_sev]:
                        sev_up += 1
                    elif sev_rank[new_sev] < sev_rank[old_sev]:
                        sev_down += 1

            elif ct == "ADDED":
                new_sev = (row.get("NEW_SEVERITY") or "").strip().upper()
                if new_sev:
                    v_added_sev[new_sev] += 1

            elif ct == "REMOVED":
                old_sev = (row.get("OLD_SEVERITY") or "").strip().upper()
                if old_sev:
                    v_removed_sev[old_sev] += 1

    #-------- Build report --------#
    lines.append(f"SCRIPT_NAME: {SCRIPT_NAME}")
    lines.append(f"SCRIPT_VERSION: {__version__}")
    lines.append(f"SCRIPT_LICENSE: {__license__}")
    lines.append("EXECUTIVE PATCH-CYCLE SUMMARY")
    lines.append("=" * 34)
    lines.append(f"RUN_TIMESTAMP: {ts}")
    lines.append("")
    lines.append("INPUTS")
    lines.append("-" * 6)
    lines.append(f"PREV_OVERVIEW: {prev_overview.resolve()}")
    lines.append(f"CURR_OVERVIEW: {curr_overview.resolve()}")
    lines.append(f"PREV_SPECS: {prev_specs.resolve() if prev_specs else ''}")
    lines.append(f"CURR_SPECS: {curr_specs.resolve() if curr_specs else ''}")
    lines.append("")

    lines.append("OUTPUTS")
    lines.append("-" * 7)
    lines.append(f"DELTA_OUT_DIR: {delta_out_dir.resolve()}")
    lines.append(f"DELTA_OVERVIEW_CSV: {delta_overview_csv.resolve()}")
    lines.append(f"DELTA_VULNS_CSV: {delta_vulns_csv.resolve() if delta_vulns_csv else 'SKIPPED/NOT_GENERATED'}")
    lines.append("")

    # Overview metrics
    lines.append("STIG-LEVEL CHANGES (OVERVIEW)")
    lines.append("-" * 28)
    lines.append(f"TOTAL_STIG_ROWS_IN_DELTA: {len(o_rows)}")
    lines.append("CHANGE_BREAKDOWN:")
    lines.extend(_fmt_counter_lines(o_change))
    lines.append("")

    if o_fields:
        lines.append("MOST COMMON STIG-LEVEL FIELD CHANGES:")
        lines.extend(_fmt_counter_lines(o_fields, limit=top_n))
        lines.append("")

    if o_by_stig:
        lines.append(f"TOP {top_n} MOST IMPACTED STIGS (BY FIELD-CHANGE SCORE):")
        lines.extend(_fmt_counter_lines(o_by_stig, limit=top_n))
        lines.append("")

    # Vuln metrics
    lines.append("VULNERABILITY-LEVEL CHANGES (SPECIFICATIONS)")
    lines.append("-" * 41)
    if not (delta_vulns_csv and delta_vulns_csv.exists()):
        lines.append("Vulnerability delta not generated (specifications not provided or invalid).")
        lines.append("")
    else:
        total_v = sum(v_change.values())
        lines.append(f"TOTAL_VULN_ROWS_IN_DELTA: {total_v}")
        lines.append("CHANGE_BREAKDOWN:")
        lines.extend(_fmt_counter_lines(v_change))
        lines.append("")

        if v_fields:
            lines.append("MOST COMMON VULN-LEVEL FIELD CHANGES:")
            lines.extend(_fmt_counter_lines(v_fields, limit=top_n))
            lines.append("")

        if v_by_stig:
            lines.append(f"TOP {top_n} STIGS WITH MOST VULN-LEVEL DELTAS:")
            lines.extend(_fmt_counter_lines(v_by_stig, limit=top_n))
            lines.append("")

        if v_added_sev:
            lines.append("ADDED VULNS BY SEVERITY:")
            lines.extend(_fmt_counter_lines(v_added_sev))
            lines.append("")

        if v_removed_sev:
            lines.append("REMOVED VULNS BY SEVERITY:")
            lines.extend(_fmt_counter_lines(v_removed_sev))
            lines.append("")

        lines.append("SEVERITY DIRECTION (CHANGED VULNS ONLY):")
        lines.append(f"  - Increased severity: {sev_up}")
        lines.append(f"  - Decreased severity: {sev_down}")
        lines.append("")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


#=================== Executive Patch-Cycle Summary END ===================#



def main():
    print(f"stig_patch_cycle_analyzer.py v{__version__}")

    # create parser and add argument
    parser = argparse.ArgumentParser(description="Module used to parse targeted DISA STIG Library and output details about STIG Manual contents (skips supplementals).")
    parser.add_argument("--target", type=str, required=False, help="Absolute path to STIG Library target.")
    parser.add_argument("--exclude-compiled-library", action="store_true", help="Exclude STIG Compilation .zip download provided by Cyber Exchange in crawl. Removes redundancy if your organization places the STIG compilation .zip in same directory as standalone STIG .zip files that are in the compiled library.")
    parser.add_argument("--out-dir", type=str, default="runs", help="Base output directory. A timestamped run folder will be created inside it.")
    parser.add_argument("--run-id", type=str, default=None, help="Optional run folder name (e.g., 'jan_patch_cycle'). Defaults to a timestamp like 20260115_173355.")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-file console output.")

    # Arguments for Delta Mode
    parser.add_argument("--delta", action="store_true", help="Generate delta CSVs comparing previous vs current outputs.")
    parser.add_argument("--prev-overview", type=str, help="Path to previous STIG_MANUALS_OVERVIEW.csv")
    parser.add_argument("--prev-specs", type=str, help="Path to previous STIG_MANUALS_SPECIFICATIONS.csv")
    parser.add_argument("--curr-overview", type=str, default="STIG_MANUALS_OVERVIEW.csv", help="Path to current overview CSV (default: STIG_MANUALS_OVERVIEW.csv).")
    parser.add_argument("--curr-specs", type=str, default="STIG_MANUALS_SPECIFICATIONS.csv", help="Path to current specs CSV (default: STIG_MANUALS_SPECIFICATIONS.csv).")
    parser.add_argument("--delta-out", type=str, default="delta_output", help="Directory to write delta CSVs into.")

    # Version check
    parser.add_argument("--version", action="store_true", help="Print version and exit.")


    args = parser.parse_args()


    # Print version and exit
    if args.version:
        print_version_banner()
        return


    # #### Delta-only path (no library parse) ####
    if args.delta and not args.target:
        if not args.prev_overview:
            raise RuntimeError("--prev-overview is required for --delta mode")
  
        prev_over = Path(args.prev_overview)
        prev_specs = Path(args.prev_specs) if args.prev_specs else None

        curr_over = Path(args.curr_overview)
        curr_specs = Path(args.curr_specs) if args.curr_specs else None

        out_dir = Path(args.delta_out)

        delta_overview_path, delta_vulns_path = generate_delta_outputs(
            prev_overview=prev_over,
            curr_overview=curr_over,
            prev_specs=prev_specs,
            curr_specs=curr_specs,
            delta_out_dir=out_dir,
            stig_key_mode="id_version_revision",
            vuln_key_mode="stig_vuln_rule"
        )


        # Optional JSON exports for delta outputs
        try:
            d_over_rows = read_csv_as_dicts(delta_overview_path)
            write_json(out_dir / "DELTA_OVERVIEW.json", d_over_rows)

            if delta_vulns_path:
                d_vuln_rows = read_csv_as_dicts(delta_vulns_path)
                write_json(out_dir / "DELTA_VULNS.json", d_vuln_rows)
        except Exception as e:
            print(f"[WARN] Delta JSON export failed: {e}")


        # Generate summary report
        write_delta_only_summary(
            out_dir,
            prev_overview=prev_over,
            curr_overview=curr_over,
            prev_specs=prev_specs,
            curr_specs=curr_specs,
            delta_overview=delta_overview_path,
            delta_vulns=delta_vulns_path
        )


        # Write Executive Summary report
        exec_summary_path = write_executive_patch_cycle_summary(
            delta_out_dir=out_dir,
            prev_overview=prev_over,
            curr_overview=curr_over,
            prev_specs=prev_specs,
            curr_specs=curr_specs,
            delta_overview_csv=delta_overview_path,
            delta_vulns_csv=delta_vulns_path,
            top_n=10
        )

        print(f"Delta-only outputs written to: {out_dir.resolve()}")


        # Generate Checksums
        script_path = Path(__file__).resolve()
        checksum_paths: list[Path] = [
            script_path,
            delta_overview_path,
            (delta_vulns_path if delta_vulns_path else None),
            out_dir / "DELTA_ONLY_SUMMARY.txt",
            exec_summary_path,
            out_dir / "DELTA_OVERVIEW.json",
            out_dir / "DELTA_VULNS.json"
        ]
        checksum_paths = [p for p in checksum_paths if isinstance(p, Path)]

        checksums_file = write_checksums(out_dir, checksum_paths)
        if not args.quiet:
            print(f"Checksums written to: {checksums_file.resolve()}")

        return



    # #### library parse path (with or without delta after) ####
    if not args.target:
        raise RuntimeError("--target is required unless you are running --delta without a crawl")

    stig_lib_path_obj = Path(rf"{args.target}")
    if not stig_lib_path_obj.is_absolute():
        raise RuntimeError("--target must be an absolute path")

    exclude_compiled_library = args.exclude_compiled_library

    # Create run folder and init outputs
    run_id = args.run_id.strip() if args.run_id else datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = "".join(c for c in run_id if c.isalnum() or c in ("-", "_", ".")) # ensure allowed dir name
    base_run_dir = Path(args.out_dir) / run_id
    run_dir = ensure_unique_run_dir(base_run_dir)

    manuals_overview, manual_specifications, run_ts_utc = init_run_outputs(run_dir, run_id=run_id)

    stig_library_parse(
        stig_lib_path_obj,
        exclude_compiled_library,
        manuals_overview,
        manual_specifications,
        quiet=args.quiet,
    )

    write_latest_run_pointer(Path(args.out_dir), run_dir)
    print(f"Run outputs written to: {run_dir.resolve()}")


    # Optional JSON exports for run outputs
    try:
        overview_rows = read_csv_as_dicts(manuals_overview)
        specs_rows = read_csv_as_dicts(manual_specifications)

        write_json(run_dir / "STIG_MANUALS_OVERVIEW.json", overview_rows)
        write_jsonl(run_dir / "STIG_MANUALS_SPECIFICATIONS.jsonl", specs_rows)
    except Exception as e:
        print(f"[WARN] JSON export failed: {e}")


    # Generate Summary report
    write_run_summary(
        run_dir,
        target=stig_lib_path_obj,
        exclude_compiled_library=exclude_compiled_library,
        quiet=args.quiet,
        manuals_overview=manuals_overview,
        manual_specifications=manual_specifications,
        stig_manual_count=len(stig_manual_catalog.keys()),
        delta_ran=False,
    )


    # Create checksums
    script_path = Path(__file__).resolve()

    checksum_paths:list[Path] = [
        script_path,
        manuals_overview,
        manual_specifications,
        run_dir / "RUN_SUMMARY.txt",
        Path(args.out_dir) / "LATEST_RUN.txt",
        run_dir / "STIG_MANUALS_OVERVIEW.json",
        run_dir / "STIG_MANUALS_SPECIFICATIONS.jsonl"
    ]


    # #### Optional: run delta after library parse ####
    if args.delta:
        if not args.prev_overview:
            raise RuntimeError("--prev-overview is required for --delta mode")

        prev_over = Path(args.prev_overview)
        prev_specs = Path(args.prev_specs) if args.prev_specs else None

        # If user didn’t override curr paths, use the freshly generated run outputs
        curr_over = Path(args.curr_overview) if args.curr_overview != "STIG_MANUALS_OVERVIEW.csv" else manuals_overview
        curr_specs = Path(args.curr_specs) if args.curr_specs != "STIG_MANUALS_SPECIFICATIONS.csv" else manual_specifications

        out_dir = Path(args.delta_out)

        delta_overview_path, delta_vulns_path = generate_delta_outputs(
            prev_overview=prev_over,
            curr_overview=curr_over,
            prev_specs=prev_specs,
            curr_specs=curr_specs,
            delta_out_dir=out_dir,
            stig_key_mode="id_version_revision",
            vuln_key_mode="stig_vuln_rule",
        )

        print(f"Delta outputs written to: {out_dir.resolve()}")


        # Optional JSON exports for delta outputs
        try:
            d_over_rows = read_csv_as_dicts(delta_overview_path)
            write_json(out_dir / "DELTA_OVERVIEW.json", d_over_rows)

            if delta_vulns_path:
                d_vuln_rows = read_csv_as_dicts(delta_vulns_path)
                write_json(out_dir / "DELTA_VULNS.json", d_vuln_rows)
        except Exception as e:
            print(f"[WARN] Delta JSON export failed: {e}")


        # Generate Summary report
        write_run_summary(
            run_dir,
            target=stig_lib_path_obj,
            exclude_compiled_library=exclude_compiled_library,
            quiet=args.quiet,
            manuals_overview=manuals_overview,
            manual_specifications=manual_specifications,
            stig_manual_count=len(stig_manual_catalog.keys()),
            delta_ran=True,
            delta_out_dir=out_dir,
            delta_overview=delta_overview_path,
            delta_vulns=delta_vulns_path,
        )

        # Write Executive Summary report
        exec_summary_path = write_executive_patch_cycle_summary(
            delta_out_dir=out_dir,
            prev_overview=prev_over,
            curr_overview=curr_over,
            prev_specs=prev_specs,
            curr_specs=curr_specs,
            delta_overview_csv=delta_overview_path,
            delta_vulns_csv=delta_vulns_path,
            top_n=10
        )

        checksum_paths.append(delta_overview_path)
        checksum_paths.append(exec_summary_path)
        checksum_paths.append(out_dir / "DELTA_OVERVIEW.json")
        checksum_paths.append(out_dir / "DELTA_VULNS.json")
        if delta_vulns_path: checksum_paths.append(delta_vulns_path)


    checksums_file = write_checksums(run_dir, checksum_paths)
    if not args.quiet:
        print(f"Checksums written to: {checksums_file.resolve()}")



if __name__ == "__main__":
    main()