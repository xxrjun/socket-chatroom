import os
import re
import fire
from typing import List


def get_file_tree(root_dir, output_file, exclude_list=[".git", "__pycache__"]):
    with open(output_file, "w", encoding="utf-8") as f:
        for root, dirs, files in os.walk(root_dir):
            dirs[:] = [d for d in dirs if d not in exclude_list]
            level = root.replace(root_dir, "").count(os.sep)
            indent = " " * 4 * level
            f.write(f"{indent}{os.path.basename(root)}/\n")
            sub_indent = " " * 4 * (level + 1)
            for file in files:
                f.write(f"{sub_indent}{file}\n")


def combine_code_files(root_dir, output_file, exclude_list=[".git", "__pycache__"]):
    with open(output_file, "w", encoding="utf-8") as f:
        for root, dirs, files in os.walk(root_dir):
            dirs[:] = [d for d in dirs if d not in exclude_list]
            for file in files:
                if file.endswith(
                    (".py", ".js", ".java", ".cpp", ".c", ".html", ".css")
                ):  # Add more extensions as needed
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, root_dir)
                    f.write(f"# {relative_path}\n```\n")

                    try:
                        with open(file_path, "r", encoding="utf-8") as code_file:
                            code = code_file.read()
                            # Remove single-line comments
                            code = re.sub(r"^\s*#.*$", "", code, flags=re.MULTILINE)
                            # Remove multi-line comments
                            code = re.sub(r"\'\'\'[\s\S]*?\'\'\'", "", code)
                            code = re.sub(r'"""[\s\S]*?"""', "", code)
                            # Remove empty lines
                            code = "\n".join(
                                line for line in code.splitlines() if line.strip()
                            )
                            f.write(code)
                    except UnicodeDecodeError:
                        f.write(
                            f"Error: Unable to read file {relative_path} due to encoding issues.\n"
                        )

                    f.write("\n```\n\n")


def main(
    root_dir: str = "../../chat",
    file_tree_output: str = "project_tree.txt",
    code_output: str = "combined_code.txt",
    exclude_list: List[str] = [".git", "__pycache__"],
):
    # Uncomment the following lines to allow user input for exclude list
    # user_exclude = input("Enter additional folders/files to exclude (comma-separated, press enter for none): ")
    # if user_exclude:
    #     exclude_list.extend([item.strip() for item in user_exclude.split(',')])

    get_file_tree(root_dir, file_tree_output, exclude_list)
    combine_code_files(root_dir, code_output, exclude_list)

    print(f"File tree saved to {file_tree_output}")
    print(f"Combined code saved to {code_output}")


if __name__ == "__main__":
    fire.Fire(main)
