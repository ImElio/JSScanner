# 🔍 JSScanner

JSScanner 1.0 is a tool for analyzing JavaScript files to extract URLs and identify sensitive keys and APIs. Designed to support developers and security researchers, it offers a streamlined approach to analyzing scripts and improving application security. 🚀

## 📜 Features

- **🔗 URL Extraction**: Finds and saves all links within JavaScript files.
- **🔑 API Key Identification**: Automatically detects various types of sensitive keys and tokens, like AWS, Google Maps, GitHub, Stripe, and more.
- **🔄 Cross-Platform Compatibility**: Optimized for both Windows and Unix-based systems (MacOS and Linux).
- **🎨 Color-Coded Output**: Utilizes `colorama` and `pystyle` for colorful, readable terminal output.

---


### Team

| Name           | Role                | Contributions                           |
|----------------|---------------------|-----------------------------------------|
| Elio           | Tool Developer      | Core functionality, secrets extraction  |
| NotKronoos     | Front-End Designer  | UI/UX                                   |


---


## 🚀 Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/your_username/JSScanner.git
    cd JSScanner
    ```
2. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3. Launch the scanner:
    ```bash
    python scanner.py --help
    ```


---

## 📖 Usage

| Functionality               | Command                                                                                             | Description                              |
|-----------------------------|-----------------------------------------------------------------------------------------------------|------------------------------------------|
| **Run Full Scan (Multiple URLs)** | ```python scanner.py <input_file.txt> -o <output_file.txt> --urls --secrets ```            | Scans a list of URLs from a file.       |
| **Run Full Scan (Single URL)**    | ```python scanner.py -u <https://example.com/script.js> --urls --secrets ```              | Scans a single URL for links & secrets. |

### Options

- **input_file**: File containing JavaScript URLs to analyze.
- **-o**, **--output_file**: File for saving extracted links (default: `extracted_links.txt`).
- **-u**, **--url**: Specify a single JavaScript URL to fetch and analyze.
- **--urls**: Extract all URLs from JavaScript content.
- **--secrets**: Identify sensitive keys and tokens within JavaScript content.


