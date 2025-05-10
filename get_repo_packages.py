import argparse
import gzip
import hashlib
import io
import os
import shutil
import socket  # For socket.timeout
import subprocess
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

try:
    from packaging.version import InvalidVersion
    from packaging.version import parse as parse_version
except ImportError:
    print(
        "Error: The 'packaging' library is not installed. Please install it to use this script."
    )
    print("You can install it by running: pip install packaging")
    sys.exit(1)


def fetch_repository_data(repo_config_url, target_architectures):
    """
    Fetches and parses RPM repository metadata.
    Stores versions in a PEP440-compatible format for keys,
    and original RPM version string in details.
    """
    print(f"Attempting to derive base URL from: {repo_config_url}")
    base_url_template = "http://linuxsoft.cern.ch/wlcg/el9/{arch}"
    # print(f"Using base URL template: {base_url_template}\n")

    all_packages = {}

    for arch in target_architectures:
        print(f"--- Processing architecture: {arch} ---")
        current_base_url = base_url_template.format(arch=arch)
        repomd_url = f"{current_base_url}/repodata/repomd.xml"
        repomd_xml_content = None

        try:
            with urllib.request.urlopen(repomd_url, timeout=30) as response:
                repomd_xml_content = response.read()
        except (urllib.error.HTTPError, urllib.error.URLError, socket.timeout) as e:
            print(f"Error fetching repomd.xml for {arch}: {e}")
            continue

        try:
            repomd_root = ET.fromstring(repomd_xml_content)
            repomd_tag_name = repomd_root.tag
            repomd_default_ns_uri = None
            if "}" in repomd_tag_name and repomd_tag_name.startswith("{"):
                repomd_default_ns_uri = repomd_tag_name.split("}")[0][1:]
            repomd_ns_map = (
                {"repo": repomd_default_ns_uri} if repomd_default_ns_uri else {}
            )

            primary_metadata_location = None
            data_elements_xpath = "repo:data" if repomd_ns_map else "data"
            for data_elem in repomd_root.findall(data_elements_xpath, repomd_ns_map):
                if data_elem.get("type") == "primary":
                    location_elem = data_elem.find(
                        "repo:location" if repomd_ns_map else "location", repomd_ns_map
                    )
                    if location_elem is not None:
                        primary_metadata_location = location_elem.get("href")
                        break

            if not primary_metadata_location:
                print(
                    f"Could not find 'primary' XML metadata location in repomd.xml for {arch}."
                )
                continue

            primary_metadata_url = f"{current_base_url}/{primary_metadata_location}"
            primary_xml_content_str = None
            with urllib.request.urlopen(primary_metadata_url, timeout=60) as response:
                if primary_metadata_url.endswith(".gz"):
                    # Use BytesIO for GzipFile as it expects a file-like object supporting read() and seek()
                    with gzip.GzipFile(fileobj=io.BytesIO(response.read())) as gz_file:
                        primary_xml_content_str = gz_file.read().decode(
                            "utf-8", errors="replace"
                        )
                else:
                    primary_xml_content_str = response.read().decode(
                        response.headers.get_content_charset() or "utf-8",
                        errors="replace",
                    )

            if not primary_xml_content_str:
                print(
                    f"Error: Could not obtain primary XML content for {arch} from {primary_metadata_url}"
                )
                continue

            primary_root = ET.fromstring(primary_xml_content_str)
            primary_tag_name = primary_root.tag
            primary_default_ns_uri = None
            if "}" in primary_tag_name and primary_tag_name.startswith("{"):
                primary_default_ns_uri = primary_tag_name.split("}")[0][1:]

            pkg_ns_map = (
                {"pkgns": primary_default_ns_uri} if primary_default_ns_uri else {}
            )

            package_count = 0
            package_xpath = "pkgns:package" if pkg_ns_map else "package"

            for package_elem in primary_root.findall(package_xpath, pkg_ns_map):
                if package_elem.get("type") != "rpm":
                    continue

                def find_text(elem, path, ns_map):
                    found = elem.find(path, ns_map)
                    return (
                        found.text.strip() if found is not None and found.text else None
                    )

                pkg_name_str = find_text(
                    package_elem, "pkgns:name" if pkg_ns_map else "name", pkg_ns_map
                )
                pkg_arch_str = find_text(
                    package_elem, "pkgns:arch" if pkg_ns_map else "arch", pkg_ns_map
                )
                version_elem = package_elem.find(
                    "pkgns:version" if pkg_ns_map else "version", pkg_ns_map
                )
                location_elem = package_elem.find(
                    "pkgns:location" if pkg_ns_map else "location", pkg_ns_map
                )

                if not (pkg_name_str and pkg_arch_str and version_elem is not None):
                    continue

                pkg_epoch = version_elem.get("epoch", "0").strip()
                pkg_ver = version_elem.get("ver", "").strip()
                pkg_rel = version_elem.get("rel", "").strip()

                if pkg_ver and pkg_rel:
                    original_rpm_version_base = f"{pkg_ver}-{pkg_rel}"
                    original_rpm_full_version = (
                        f"{pkg_epoch}:{original_rpm_version_base}"
                        if pkg_epoch != "0"
                        else original_rpm_version_base
                    )

                    pep440_ver_rel_part = f"{pkg_ver}+{pkg_rel.replace('-', '.')}"  # Replace '-' in release with '.' for local version
                    pep440_version_str = (
                        f"{pkg_epoch}!{pep440_ver_rel_part}"
                        if pkg_epoch != "0"
                        else pep440_ver_rel_part
                    )

                    try:
                        parse_version(pep440_version_str)
                    except InvalidVersion:
                        # Fallback for complex release tags if simple '+' replacement fails
                        # Example: 1.2.3-4.beta.el9 -> 1.2.3+4.beta.el9 (might need more robust transformation)
                        # For now, we assume pkg_ver is clean and pkg_rel is the problematic part.
                        # A common strategy is to replace all non-alphanumeric in pkg_rel with dots.
                        safe_rel = "".join(
                            c if c.isalnum() else "." for c in pkg_rel
                        ).strip(".")
                        pep440_ver_rel_part_alt = f"{pkg_ver}+{safe_rel}"
                        pep440_version_str_alt = (
                            f"{pkg_epoch}!{pep440_ver_rel_part_alt}"
                            if pkg_epoch != "0"
                            else pep440_ver_rel_part_alt
                        )
                        try:
                            parse_version(pep440_version_str_alt)
                            pep440_version_str = (
                                pep440_version_str_alt  # Use alternative if it parses
                            )
                        except InvalidVersion:
                            # print(f"  Debug: Failed to parse generated PEP440 string '{pep440_version_str}' (and alt '{pep440_version_str_alt}') from ver='{pkg_ver}', rel='{pkg_rel}', epoch='{pkg_epoch}'. Skipping package {pkg_name_str}.")
                            continue

                    pkg_download_url = None
                    if location_elem is not None and location_elem.get("href"):
                        relative_path = location_elem.get("href")
                        pkg_download_url = f"{current_base_url}/{relative_path}"

                    checksum_xpath = "pkgns:checksum" if pkg_ns_map else "checksum"
                    pkg_checksum_type = None
                    pkg_checksum_value = None
                    available_checksums = {}
                    for chk_elem in package_elem.findall(checksum_xpath, pkg_ns_map):
                        chk_type = chk_elem.get("type")
                        chk_val = chk_elem.text
                        if chk_type and chk_val:
                            available_checksums[chk_type.lower()] = chk_val.strip()

                    preferred_checksums = ["sha256", "sha512", "sha1", "md5"]
                    for chk_t in preferred_checksums:
                        if chk_t in available_checksums:
                            pkg_checksum_type = chk_t
                            pkg_checksum_value = available_checksums[chk_t]
                            break
                    if not pkg_checksum_type and available_checksums:
                        first_type = sorted(available_checksums.keys())[0]
                        pkg_checksum_type = first_type
                        pkg_checksum_value = available_checksums[first_type]

                    package_key = (pkg_name_str, pep440_version_str, pkg_arch_str)
                    if package_key not in all_packages:
                        all_packages[package_key] = {
                            "url": pkg_download_url,
                            "checksum_type": pkg_checksum_type,
                            "checksum_value": pkg_checksum_value,
                            "original_rpm_version": original_rpm_full_version,
                        }
                        package_count += 1

            print(f"Found {package_count} new unique packages for architecture {arch}.")

        except ET.ParseError as e:
            print(f"Error parsing XML for {arch}: {e}")
        except gzip.BadGzipFile:
            print(f"Error: Bad Gzip file encountered for {primary_metadata_url}.")
        except (urllib.error.HTTPError, urllib.error.URLError, socket.timeout) as e:
            print(
                f"Error during network request for primary metadata or other issue in {arch}: {e}"
            )
        except Exception as e:
            print(
                f"An unexpected error occurred while processing {arch}: {e} (Type: {type(e)})"
            )

        print(f"--- Finished processing architecture: {arch} ---\n")

    return all_packages


def print_package_summary(packages_info):
    print("\n--- Summary of all unique packages found ---")
    if packages_info:

        def sort_key_func(key_tuple):
            name, pep440_version_str, arch = key_tuple
            return (name.lower(), arch, parse_version(pep440_version_str))

        sorted_package_keys = sorted(list(packages_info.keys()), key=sort_key_func)

        for name, pep440_version, pkg_arch_key in sorted_package_keys:
            details = packages_info[(name, pep440_version, pkg_arch_key)]
            display_version = details.get("original_rpm_version", pep440_version)

            print(f"Package: {name}, Version: {display_version}, Arch: {pkg_arch_key}")
        print(f"\nTotal unique package entries found: {len(packages_info)}")
    else:
        print("No packages found.")


def calculate_file_checksum(file_path, hash_algorithm="sha256"):
    hash_algorithm = hash_algorithm.lower()
    try:
        hasher = hashlib.new(hash_algorithm)
    except ValueError:
        return None
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def download_and_extract_matching_packages(
    all_packages_info,
    package_name_filter,
    download_dir,
    extract_dir,
    rpm2cpio_path,
    cpio_path,
):
    print(
        f"\n--- Selecting Latest Versions for Packages Matching Filter: '{package_name_filter}' ---"
    )
    # Ensure the main download and extract directories exist
    os.makedirs(download_dir, exist_ok=True)
    os.makedirs(extract_dir, exist_ok=True)

    latest_versions_to_process = {}

    for original_key, details_dict in all_packages_info.items():
        pkg_name, pep440_version_str, pkg_arch = original_key

        if package_name_filter.lower() not in pkg_name.lower():
            continue

        name_arch_key = (pkg_name, pkg_arch)
        try:
            current_pkg_version_obj = parse_version(pep440_version_str)
        except InvalidVersion as ive:
            print(
                f"  Warning: Could not parse PEP440 version string '{pep440_version_str}' for '{pkg_name}' (arch: '{pkg_arch}')."
            )
            print(
                f"    Original RPM version was: {details_dict.get('original_rpm_version', 'N/A')}"
            )
            print(f"    Exception: {ive}. Skipping this entry.")
            continue
        except Exception as e:
            print(
                f"  Warning: Unexpected error parsing version '{pep440_version_str}' for {pkg_name} ({pkg_arch}): {e}. Skipping."
            )
            continue

        if name_arch_key not in latest_versions_to_process:
            latest_versions_to_process[name_arch_key] = {
                "original_key": original_key,
                "version_obj": current_pkg_version_obj,
                "details": details_dict,
            }
        else:
            stored_version_obj = latest_versions_to_process[name_arch_key][
                "version_obj"
            ]
            if current_pkg_version_obj > stored_version_obj:
                latest_versions_to_process[name_arch_key] = {
                    "original_key": original_key,
                    "version_obj": current_pkg_version_obj,
                    "details": details_dict,
                }

    if not latest_versions_to_process:
        print(
            f"No packages found matching filter '{package_name_filter}' or no valid versions to compare after filtering."
        )
        return

    print(
        f"\n--- Will Download and Extract {len(latest_versions_to_process)} Latest Package(s) ---"
    )
    processed_count = 0
    for item_to_process in latest_versions_to_process.values():
        pkg_name, _, pkg_arch = item_to_process["original_key"]
        details = item_to_process["details"]
        rpm_version_for_file = details["original_rpm_version"]

        processed_count += 1
        print(
            f"\nProcessing [{processed_count}/{len(latest_versions_to_process)}] latest package: {pkg_name}-{rpm_version_for_file}.{pkg_arch}"
        )

        if not details["url"]:
            print(f"  Skipping {pkg_name}: No download URL available.")
            continue

        pkg_url = details["url"]
        rpm_filename = f"{pkg_name}-{rpm_version_for_file}.{pkg_arch}.rpm"
        local_rpm_path = os.path.join(download_dir, rpm_filename)

        print(f"  Downloading {pkg_url} to {local_rpm_path}...")
        try:
            with (
                urllib.request.urlopen(pkg_url, timeout=120) as response,
                open(local_rpm_path, "wb") as out_file,
            ):
                shutil.copyfileobj(response, out_file)
            print(f"  Downloaded {rpm_filename}.")
        except (urllib.error.HTTPError, urllib.error.URLError, socket.timeout) as e:
            print(f"  Error downloading {pkg_url}: {e}")
            if os.path.exists(local_rpm_path):
                os.remove(local_rpm_path)
            continue
        except Exception as e:
            print(f"  An unexpected error occurred during download of {pkg_url}: {e}")
            if os.path.exists(local_rpm_path):
                os.remove(local_rpm_path)
            continue

        if details["checksum_type"] and details["checksum_value"]:
            checksum_algo = details["checksum_type"]
            expected_checksum = details["checksum_value"]
            supported_checksum_algos = ["sha256", "sha512", "sha1", "md5"]
            if checksum_algo in supported_checksum_algos:
                actual_checksum = calculate_file_checksum(local_rpm_path, checksum_algo)
                if actual_checksum:
                    if actual_checksum.lower() == expected_checksum.lower():
                        print(f"  Checksum VERIFIED ({checksum_algo}).")
                    else:
                        print(
                            f"  WARNING: Checksum MISMATCH for {rpm_filename} ({checksum_algo}). Expected: {expected_checksum}, Actual: {actual_checksum}"
                        )

        # --- MODIFIED EXTRACTION LOGIC ---
        # Files will be extracted directly into extract_dir
        # The extract_dir itself is already created at the beginning of this function.
        current_extract_path = extract_dir

        rpm_file_abs_path = os.path.abspath(local_rpm_path)
        cmd_rpm2cpio = [rpm2cpio_path, rpm_file_abs_path]
        cmd_cpio = [
            cpio_path,
            "-idmv",
        ]  # -i extract, -d create dirs if needed, -m preserve mod times, -v verbose (lists files)

        print(f"  Extracting {rpm_filename} to '{current_extract_path}'...")
        try:
            p_rpm2cpio = subprocess.Popen(
                cmd_rpm2cpio, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            # Set cwd for cpio to be the main extract_dir
            p_cpio = subprocess.Popen(
                cmd_cpio,
                stdin=p_rpm2cpio.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=current_extract_path,
            )

            if p_rpm2cpio.stdout:
                p_rpm2cpio.stdout.close()

            cpio_stdout, cpio_stderr = p_cpio.communicate(timeout=120)

            rpm2cpio_stderr_output = b""
            if p_rpm2cpio.stderr:
                rpm2cpio_stderr_output = p_rpm2cpio.stderr.read()
                p_rpm2cpio.stderr.close()

            p_rpm2cpio.wait(timeout=10)

            if p_cpio.returncode == 0:
                print(
                    f"  Successfully extracted {rpm_filename} to '{current_extract_path}'"
                )
                if cpio_stdout and cpio_stdout.strip():
                    # cpio -v lists extracted files, count them
                    num_files_extracted = len(
                        cpio_stdout.decode(errors="ignore").splitlines()
                    )
                    print(
                        f"    {num_files_extracted} file(s)/directory(s) processed by cpio."
                    )
            else:
                print(
                    f"  Error during extraction of {rpm_filename}: rpm2cpio_rc={p_rpm2cpio.returncode}, cpio_rc={p_cpio.returncode}"
                )
                if rpm2cpio_stderr_output:
                    print(
                        f"    rpm2cpio stderr: {rpm2cpio_stderr_output.decode(errors='ignore')}"
                    )
                if cpio_stderr:
                    print(f"    cpio stderr: {cpio_stderr.decode(errors='ignore')}")
        except subprocess.TimeoutExpired:
            print(f"  Timeout expired during extraction of {rpm_filename}.")
            # Ensure processes are killed if they exist and are running
            if "p_rpm2cpio" in locals() and p_rpm2cpio.poll() is None:
                p_rpm2cpio.kill()
            if "p_cpio" in locals() and p_cpio.poll() is None:
                p_cpio.kill()
            # Attempt to communicate again to free resources
            if "p_rpm2cpio" in locals():
                p_rpm2cpio.communicate()
            if "p_cpio" in locals():
                p_cpio.communicate()
        except Exception as e:
            print(
                f"  An unexpected error occurred during extraction of {rpm_filename}: {e}"
            )

    if processed_count > 0:
        print(
            f"\n--- Finished downloading and extracting {processed_count} latest matched package(s) ---"
        )
    elif len(latest_versions_to_process) > 0:
        print(
            f"No packages were ultimately processed despite matching the filter '{package_name_filter}'. Check for download/extraction errors above."
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fetch WLCG repository package information, and optionally download and extract the LATEST versions of packages.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--filter",
        type=str,
        help="Substring to filter package names for download and extraction (case-insensitive). Only the latest version of matching packages (per architecture) will be processed.",
    )
    parser.add_argument(
        "--download-dir",
        type=str,
        default="downloaded_rpms",
        help="Directory to save downloaded RPMs (default: ./downloaded_rpms).",
    )
    parser.add_argument(
        "--extract-dir",
        type=str,
        default="extracted_rpms",
        help="Directory to extract RPM contents (default: ./extracted_rpms).\nAll files from matching RPMs will be extracted directly into this directory.\nWARNING: Files from different RPMs with the same path will overwrite each other.",
    )
    parser.add_argument(
        "--archs",
        type=str,
        default="x86_64,aarch64,noarch",
        help="Comma-separated list of architectures to scan (default: x86_64,aarch64,noarch).",
    )
    parser.add_argument(
        "--list-only",
        action="store_true",
        help="Only fetch and list package information, do not prompt for filter or perform downloads/extractions.",
    )

    args = parser.parse_args()

    repo_file_url_for_reference = "https://linuxsoft.cern.ch/wlcg/wlcg-el9.repo"
    architectures_to_scan = [
        arch.strip() for arch in args.archs.split(",") if arch.strip()
    ]

    all_packages_info = fetch_repository_data(
        repo_file_url_for_reference, architectures_to_scan
    )
    print_package_summary(all_packages_info)

    if args.list_only:
        print("\n--list-only specified. Exiting after listing packages.")
    elif args.filter:
        if not all_packages_info:
            print(
                "\nNo package information was fetched. Cannot proceed with download/extraction."
            )
        else:
            rpm2cpio_exe = shutil.which("rpm2cpio")
            cpio_exe = shutil.which("cpio")
            if not rpm2cpio_exe or not cpio_exe:
                missing = []
                if not rpm2cpio_exe:
                    missing.append("'rpm2cpio'")
                if not cpio_exe:
                    missing.append("'cpio'")
                print(
                    f"Error: {', '.join(missing)} not found. Please install them. Skipping download/extraction."
                )
            else:
                download_and_extract_matching_packages(
                    all_packages_info,
                    args.filter,
                    args.download_dir,
                    args.extract_dir,  # Corrected variable name here
                    rpm2cpio_exe,
                    cpio_exe,
                )
    elif len(sys.argv) > 1:
        print(
            "\nNo --filter provided for download/extraction. Use --filter <substring> or --list-only."
        )
