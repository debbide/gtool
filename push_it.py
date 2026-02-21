import subprocess
import os

def run_git():
    repo_dir = r"e:\ck\tools-standalone\file-manager-project\go-version"
    os.chdir(repo_dir)
    
    try:
        print("Staging all changes...")
        subprocess.run(["git", "add", "."], check=True)
        
        print("Committing...")
        # We use a generic commit message since we are force-syncing
        subprocess.run(["git", "commit", "-m", "chore: manual sync via Python script"], check=True)
        
        print("Pushing to main branch...")
        subprocess.run(["git", "push", "origin", "main"], check=True)
        print("Successfully pushed!")
    except subprocess.CalledProcessError as e:
        print(f"Git command failed: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    run_git()
