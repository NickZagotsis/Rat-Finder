# RatFinder 🐀

## Introduction

### Remote Access Tools

Remote access tools are designed to make IT support, system monitoring, and real-time 
collaboration easier and more efficient.

However, while these tools undoubtedly offer great flexibility and convenience, 
they can also be easily misused by malicious actors if the necessary precautions aren't taken. 

Many of these tools, such as AnyDesk and TeamViewer, are free and readily available to anyone, 
making it all the more important to understand their capabilities.

With this in mind, RatFinder is developed to support digital forensic examiners in identifying and 
attributing malicious remote access tool activity to the threat actors they work to defend against.

### About

RatFinder is a `Python` application, designed to be used as a triage and/or
post-acquisition tool.

### Purpose

- **Quick identification of RAT artifacts during triage.**
- **Generate concise reports for further analysis.**
- **Help correlate malicious actions to their actors.**

### How it works

RatFinder scans either acquired forensic artifacts 
or live systems for signs of commonly used remote access software.
It parses known indicator patterns - such as log files, registry hives, 
and configuration files - and highlights any potential matches.
The results can be exported in multiple 
formats for continued investigation or documentation.

### Features

- **Currently supports AnyDesk and TeamViewer**
- **Clean and user-friendly GUI**
- **Parses RAT-related artifacts**
- **Supports both live analysis and post-acquisition data**
- **Generates reports in CSV, Excel, and HTML formats**

### How to use

There are two ways to run RatFinder:
1. **Using the source code**

    Clone or download the repository and 
    install the required dependencies listed in `requirements.txt`:
    
    ```bash
   pip install -r requirements.txt
   cd ..
   python -m RatFinder.main
   ```

2. **Using the pre-built binary**
    
    Download the latest release from the [releases](https://github.com/NickZagotsis/RatFinder/releases) section

> Note: The standalone binary is recommended for field use, 
> as it can be easily transported and executed on infected systems 
> without requiring Python or additional setup.

### Reports explanation

1. CSV

   * Flat structure, readable by most spreadsheet tools.

   * One file per artifact type (e.g., anydesk_results.csv, teamviewer_logs.csv).

2. EXCEL

   * Same data as CSV.
   
   * Key fields (e.g., suspicious log entries, file transfers) are highlighted in red.
   
   * Designed for fast visual scanning and filtering.


3. HTML

   * Fully interactive reports rendered using Jinja2 templates.
   
   * Tables support filtering, sorting, and client-specific drill-down views.
   
   * Includes:
   
     * Session summaries

      * Transferred file lists
      
      * IP geolocation
      
      * Notable events with contextual explanations
      
      * External lookup links (e.g., VirusTotal, IP-API)
   * HTML reports are organized into:

       * general_report.html – main dashboard
   
       * user-specific.html – individual client sessions, IPs, and actions
   
   >  Note: Open these in a modern browser (Chrome, Firefox) for best results.
   
### Limitations

   * Tested only on free versions of AnyDesk and TeamViewer.
   
   * Does not yet support Linux/macOS artifacts.
   
   * Not tested on enterprise-scale data.
   
   * IP resolution depends on third-party services (e.g., ip-api.com), which may have rate limits.

### License

This project is distributed for **non-commercial, educational, and research use only**.  
Commercial use is strictly prohibited. Redistribution must preserve this notice.  
See the [LICENSE](./LICENSE) file for full terms.

### Author

**Nikolaos Zagotsis**

Bachelor’s Thesis – Department of Informatics, University of Piraeus (2025)

GitHub: [@NickZagotsis](https://github.com/NickZagotsis)