#!/usr/bin/env python3


import shutil
import json
from pathlib import Path
from datetime import datetime


# File categories
CATEGORIES = {
    "documents": ["pdf", "doc", "docx", "txt", "xlsx", "pptx"],
    "images": ["jpg", "jpeg", "png", "gif", "bmp"],
    "archives": ["zip", "tar", "gz", "rar"],
    "executables": ["exe", "msi", "dmg"],
    "videos": ["mp4", "mov", "avi", "mkv"],
    "audio": ["mp3", "wav", "aac"],
    "other": []
}


def get_extension(filename):
    """Extract file extension safely"""
    if "." not in filename:
        return ""
    return filename.split(".")[-1].lower()


def get_category(extension):
    """Determine category based on extension"""
    for category, extensions in CATEGORIES.items():
        if extension in extensions:
            return category
    return "other"


def move_file(file_path, category, stats, errors):
    """Move file to category folder safely"""
    try:
        destination_folder = file_path.parent / category
        destination_folder.mkdir(exist_ok=True)

        destination = destination_folder / file_path.name

        if destination.exists():
            errors.append(f"File exists: {file_path.name}")
            return

        shutil.move(str(file_path), str(destination))
        stats[category] += 1

    except Exception as e:
        errors.append(f"{file_path.name}: {str(e)}")


def generate_json_report(stats, source_dir, errors):

    report_path = Path(__file__).parent / "organizer_report.json"

    report = {
        "timestamp": datetime.now().isoformat(),
        "source_directory": str(source_dir),
        "statistics": stats,
        "errors": errors
    }

    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)


def generate_text_report(stats, total_files, errors):

    report_path = Path(__file__).parent / "organizer_report.txt"

    with open(report_path, "w") as f:

        f.write("SMART DOWNLOADS ORGANIZER REPORT\n")
        f.write("================================\n\n")

        f.write(f"Total files processed: {total_files}\n\n")

        for category, count in stats.items():
            percent = (count / total_files * 100) if total_files else 0
            f.write(f"{category}: {count} files ({percent:.1f}%)\n")

        f.write("\nErrors:\n")

        if errors:
            for error in errors:
                f.write(error + "\n")
        else:
            f.write("None\n")


def main():

    source_dir = Path("test_files")

    if not source_dir.exists():
        print("Directory not found")
        return

    stats = {category: 0 for category in CATEGORIES}
    errors = []

    files = [f for f in source_dir.iterdir() if f.is_file()]

    total_files = len(files)

    for file in files:

        extension = get_extension(file.name)
        category = get_category(extension)

        move_file(file, category, stats, errors)

    generate_json_report(stats, source_dir, errors)
    generate_text_report(stats, total_files, errors)

    print("Organization complete.")
    print(f"Processed {total_files} files.")


if __name__ == "__main__":
    main()
