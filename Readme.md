This is a fork of the vigiles-openwrt SBOM generation tool but with a changed output thus you can generate a CycloneDX SBOM usable for dependency track.
This tool needs valid CPE IDs in the OpenWRT package Makefiles. No other source is used! Packages without a valid CPE ID cannot be tracked. You can use debug mode to see what is skipped.

Usage: 
1. checkout configure and build a complete OpenWRT tree with specific selected packages
2. run this tool on the main OpenWRT tree directory: "sbom-openwrt.py -b <your-openwrt-dir>"
3. pick the sbom which will be placed within the newly generated sbom-output directory
4. upload the sbom to your personal dependency track server

Links:

https://dependencytrack.org/

https://cyclonedx.org/

What no longer works compared to the Timesys service:
* The original tool from Timesys parses kernel and uboot configs too for their service upload. There is counterpart for such
  a thing in dependency track.
* CVE patches in OpenWRT patch file syntax are detected but cannot be passed to dependency track as well