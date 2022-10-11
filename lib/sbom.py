###########################################################################
#
# lib/sbom.py - Helper for generation cycloneDX SBOM
#
# Copyright (C) 2022 ads-tec Engineering GmbH
#
#
# This source is released under the MIT License.
#
###########################################################################
import json

from lib.manifest import _init_manifest, _manifest_name
from lib.utils import dbg, mkdirhier, info

CYCLONE_SPEC_VERSION = "1.4"


def filter_non_cpe_packages(packages):
    for package_name in list(packages.keys()):
        curr_package_values = packages.get(package_name)
        if curr_package_values.get("cpe_id") == "unknown" or curr_package_values.get("cpe_id") is None:
            dbg(f"Remove Non-CPE-Package: {package_name} from list")
            del packages[package_name]
    return packages


def fill_in_package_info(packages, components_list):
    name_list = []
    for package_name in list(packages.keys()):
        curr_package = packages.get(package_name)
        if not curr_package.get("name") in name_list:
            name_list.append(curr_package.get("name"))
            append = True
        else:
            append = False
            for component in components_list:
                if curr_package.get("name") == component.get("name"):
                    if curr_package.get("version") != component.get("version"):
                        append = True
                        break

        if append:
            components_list.append(
                {
                    "type": "application",
                    "supplier": {
                        "name": curr_package.get("package_supplier")
                    },
                    "name": curr_package.get("name"),
                    "version": curr_package.get("version"),
                    "licenses": [
                        {
                            "license": {
                                "name": curr_package.get("license")
                            }
                        }
                    ],
                    "cpe": curr_package.get("cpe_id") + ":" + curr_package.get("version"),
                }
            )


def generate_cyclone_sbom(packages):
    cyclone_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONE_SPEC_VERSION,
        "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
        "version": 1,
        "components": []
    }
    fill_in_package_info(packages, cyclone_sbom["components"])
    return cyclone_sbom


def convert_sbom_to_cyclonesbom(packages):
    packages = filter_non_cpe_packages(packages)
    cyclone_sbom = generate_cyclone_sbom(packages)
    return cyclone_sbom


def write_manifest_cyclonesbom(params):
    final = _init_manifest(params)
    cyclone_sbom = convert_sbom_to_cyclonesbom(params["packages"])
    mkdirhier(params["odir"])
    params["manifest"] = _manifest_name(params, final)
    info("Writing Manifest to %s" % params["manifest"])
    with open(params["manifest"], "w") as f:
        json.dump(cyclone_sbom, f, indent=4, separators=(",", ": "), sort_keys=True)
        f.write("\n")
