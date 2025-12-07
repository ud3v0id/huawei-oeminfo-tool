# Huawei/Honor OEMInfo Tool

A robust, high-performance, and secure command-line tool for analyzing, unpacking, and repacking `oeminfo.img` files found in Huawei and Honor devices (EMUI / MagicOS).

This tool allows developers and ROM modders to inspect the proprietary `oeminfo` partition structure, extract data blocks (including images, logs, and configuration files), and rebuild the image after modification.

## 🚀 Features

*   **Comprehensive Parsing**: Automatically detects and classifies data blocks:
    *   **Standard Blocks**: 4KB aligned blocks.
    *   **Reused Blocks**: Efficient storage for repeated data.
    *   **Images**: Auto-detection of GZIP and BMP boot logos/animations.
    *   **TLV Data**: Parses Type-Length-Value structures automatically.
    *   **Text/Configuration**: Identifies and previews ASCII/UTF-8 content.
*   **High Performance**:
    *   **Streaming I/O**: Uses stream-based processing for repacking, allowing manipulation of large images with minimal RAM usage.
    *   **Optimized Search**: Utilizes pre-compiled structs and C-level byte comparison for extremely fast padding and header scanning.
*   **Secure & Robust**:
    *   **Path Traversal Protection**: Prevents malicious filenames from writing outside the target directory.
    *   **Atomic Writes**: Uses temporary files during repacking to ensure the output file is never corrupted if the process is interrupted.
*   **User Friendly**: 
    *   Detailed ASCII previews for text blocks.
    *   Structured `manifest.json` for easy modification and rebuilding.
    *   Verbose debug logging.

## 📋 Requirements

*   Python 3.6+
*   Standard libraries only (No `pip install` required).

## 🛠️ Usage

### 1. List Content
Quickly view the contents of an image without extracting files.

```bash
python oeminfo_tool.py list -i oeminfo.img
```

**Options:**
*   `-p`, `--preview`: Show a text preview of ASCII data blocks.
*   `-d`, `--debug`: Enable detailed debug logging.

### 2. Unpack
Extract all data blocks into a directory. This generates a `manifest.json` file required for repacking.

```bash
python oeminfo_tool.py unpack -i oeminfo.img -o output_folder
```

**Output Structure:**
```text
output_folder/
├── manifest.json               # Layout and metadata definition
├── 15_1_standard_active.txt    # Extracted text block
├── 351_28_standard_active.gz   # Extracted boot animation (GZIP)
└── ...
```

**Options:**
*   `-f`, `--force`: Force overwrite if the output directory already exists.

### 3. Repack
Rebuild an `oeminfo.img` file from an extracted directory. You can modify the files or the `manifest.json` before repacking.

```bash
python oeminfo_tool.py repack -i output_folder -o new_oeminfo.img
```

**Note:** The tool automatically handles padding calculation and block alignment (0x1000 for Standard, 0x80 for Reused).

**Options:**
*   `-f`, `--force`: Force overwrite if the output file already exists.

## 🛡️ Safety & Architecture

This tool works by mapping the original file structure into a `manifest.json`.
*   **Unpacking**: It safely extracts data, detecting file types (GZIP/BMP/Text) and adding appropriate extensions.
*   **Repacking**: It reads the `manifest.json`, reconstructs the specific OEM headers, and stitches the file back together.

**Atomic Write Mechanism**:
When repacking, the tool writes to `filename.img.tmp` first. Only after a successful write is the file renamed to the final `filename.img`. This prevents data loss or corruption of existing files during a crash.

## ⚠️ Disclaimer

This tool is for educational and research purposes only. Modifying critical system partitions like `oeminfo` carries a risk of bricking your device. Always keep a backup of your original partition. The author is not responsible for any damage caused by the use of this tool.

## 📄 License

MIT License
