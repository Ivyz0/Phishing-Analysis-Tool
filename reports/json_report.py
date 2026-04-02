import json
import os


def write_json_report(report: dict, output_path: str) -> None:
    output_folder = os.path.dirname(output_path)

    if output_folder != "":
        os.makedirs(output_folder, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as output_file:
        json.dump(report, output_file, indent=2, ensure_ascii=False)
