import argparse
import logging
import os
import sys

import pandas as pd
from pypdf import PdfReader

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def setup_argparse():
    """Sets up the argument parser for the CLI."""
    parser = argparse.ArgumentParser(
        description="Extracts and analyzes metadata from PDF files."
    )
    parser.add_argument(
        "pdf_file",
        help="Path to the PDF file to analyze.",
        type=str,
    )  # Make pdf_file a positional argument
    parser.add_argument(
        "--output",
        "-o",
        help="Path to the output CSV file (optional).",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging.",
    )
    parser.add_argument(
        "--check-modified",
        action="store_true",
        help="Check for modification date (may indicate tampering).",
    )

    return parser


def extract_metadata(pdf_path):
    """Extracts metadata from a PDF file."""
    try:
        with open(pdf_path, "rb"):
            reader = PdfReader(pdf_path)
            metadata = reader.metadata
            if metadata:
                return dict(metadata)
            else:
                logging.warning(
                    "No metadata found in PDF file: %s", pdf_path
                )
                return {}  # Return empty dictionary to avoid errors
    except FileNotFoundError:
        logging.error("File not found: %s", pdf_path)
        raise  # Re-raise for handling in main()
    except Exception as e:
        logging.error("Error reading PDF file: %s - %s", pdf_path, e)
        raise  # Re-raise for handling in main()


def analyze_metadata(metadata, check_modified=False):
    """Analyzes the extracted metadata for suspicious entries."""
    analysis_results = {}

    # Check for common suspicious metadata keys
    suspicious_keys = [
        "xmp:CreatorTool",
        "pdf:Producer",
        "dc:creator",
        "author",
        "creator",
        "producer",
        "title",
    ]

    for key in suspicious_keys:
        if key in metadata:
            analysis_results[f"Suspicious Key: {key}"] = metadata[key]

    # Check for unusual modification dates
    if check_modified:
        if "/ModDate" in metadata:  # using raw key as the metadata is dynamic.
            analysis_results["Modification Date"] = metadata["/ModDate"]  # using raw key
        else:
            logging.warning("Modification date not found in metadata.")

    # Perform basic checks for inconsistencies
    if "author" in metadata and "creator" in metadata:
        if metadata["author"] != metadata["creator"]:
            analysis_results["Author/Creator Mismatch"] = "Possible inconsistency detected."

    if not analysis_results:
        logging.info("No suspicious metadata found.")

    return analysis_results


def save_to_csv(data, output_path):
    """Saves the analysis results to a CSV file."""
    try:
        df = pd.DataFrame.from_dict(data, orient="index", columns=["Value"])
        df.to_csv(output_path)
        logging.info("Analysis results saved to: %s", output_path)
    except Exception as e:
        logging.error("Error saving to CSV: %s - %s", output_path, e)


def main():
    """Main function to orchestrate the metadata extraction and analysis."""
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)  # Set logging level to DEBUG

    logging.debug("PDF file: %s", args.pdf_file)
    logging.debug("Output file: %s", args.output)

    try:
        metadata = extract_metadata(args.pdf_file)
        analysis_results = analyze_metadata(metadata, args.check_modified)

        if analysis_results:
            print("Analysis Results:")
            for key, value in analysis_results.items():
                print(f"{key}: {value}")

            if args.output:
                save_to_csv(analysis_results, args.output)
        else:
            print("No suspicious metadata found.")

    except FileNotFoundError:
        print(f"Error: File not found: {args.pdf_file}")
        sys.exit(1)  # Exit with an error code
    except Exception as e:  # Catch all other exceptions
        print(f"An error occurred: {e}")
        sys.exit(1)  # Exit with an error code

if __name__ == "__main__":
    main()

# Example Usage:
# 1. Analyze a PDF file:
#    python main.py suspicious.pdf
#
# 2. Analyze a PDF file and save the output to a CSV:
#    python main.py suspicious.pdf -o output.csv
#
# 3. Analyze a PDF with verbose logging:
#    python main.py suspicious.pdf -v
#
# 4. Analyze PDF file, output CSV and check if the file has been modified
#    python main.py suspicious.pdf -o output.csv --check-modified