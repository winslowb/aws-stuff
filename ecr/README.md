🐳 ###create_ecr_repo_and_creds.py

A realistic, mildly frustrated, slightly festive tool to create AWS IAM roles and ECR repositories so users can push Docker images—without having to do everything manually. Meant for internal dev workflows where people just need creds and a place to push containers.

✨ ###What It Does
Creates an IAM role for a user to push images to an ECR repo

Assumes the role and gives you temporary credentials

Creates a uniquely named ECR repo if it doesn't exist

Attaches IAM policies to allow image push actions

(Tries to) apply ECR repository policies

Spits out ready-to-export AWS credentials and a docker login command

Leaves cleanup logic in place for future paranoia or automation

🧪 Why It Exists
I tried to prevent cross-repository uploads using IAM roles and policies, but AWS didn't make it easy (or possible?). I then tried attaching policies to the repos directly—same story. So I settled for a script that mostly works, with manual policy application as a fallback. If you figure that part out, send help (or a PR).

📦 Requirements
Python 3.6+

boto3

AWS CLI config with named profiles for each target environment

Install requirements:

bash
Copy
Edit
pip install boto3
🚀 Usage
bash
Copy
Edit
python create_ecr_repo_and_creds.py
You'll be prompted to:

Select an AWS CLI profile

Enter a username

Choose an environment (like brh staging or brh prod)

After that, the script will:

Escape the username into something ECR-safe

Create an IAM role and attach the right policies

Create an ECR repository (if needed)

Return temporary AWS credentials

Output docker login and docker push instructions

🧹 Cleanup
Temporary credentials expire on their own. There’s a schedule_cleanup() function if you ever want to automatically delete roles after expiration, but it's currently unused.

🔥 Known Weirdness
Applying repository-level policies via boto3 doesn’t work. I’ve tried dicts, strings, charms, etc. You can apply them manually with aws ecr set-repository-policy.

There's a directory called test/ with a working policy file I used manually. It's not referenced directly here but might help.

🎄 Notes
I wrote this before taking some time off. If you’re reading it and feel like hacking away—go for it. Happy holidays.

📜 License
MIT or something equally chill. Use it, break it, fix it, share it.


