# Git Commands for Branch Management and Collaboration

## Creating and Managing Branches

### Create a New Branch
\```bash
git branch [branch name] # Creates a new branch with the specified name
\```

### Switch to a Branch
\```bash
git checkout [branch name] # Switches to the specified branch
\```

### View Branches
\```bash
git branch -a # Lists all local and remote branches
\```

### Delete a Branch
\```bash
git branch --merged # Lists branches that have been merged into the current branch
git branch -d [branch name] # Deletes the specified branch locally
git push origin --delete [branch name] # Deletes the specified branch from the remote repository
\```

## Staging and Committing Changes

### Check Status
\```bash
git status # Shows changes that will be committed on the current branch
\```

### Stage Changes
\```bash
git add . # Stages all files in the current working directory
\```

### Commit Changes
\```bash
git commit -m "Basic code commit comment" # Commits staged changes with a message
\```

## Pushing and Pulling Changes

### Push Changes to Remote Repository
\```bash
git push -u origin [branch name] # Pushes changes to the specified branch on the remote repository and sets the upstream branch
\```

### Pull Changes from Remote Repository
\```bash
git pull origin master # Pulls in all changes from the master branch on the remote repository
\```

## Merging Branches

### Merge a Branch into the Current Branch
\```bash
git merge [branch name] # Merges the specified branch into the current branch
\```

### Push Merged Changes
\```bash
git push origin [branch name] # Pushes merged changes to the specified branch on the remote repository
\```

## Viewing Repository Information

### View Remote Repository Information
\```bash
git remote -v # Shows information about the remote repository
\```

## Reviewing Changes

### View Differences
\```bash
git diff # Shows changes made to the code that are not yet staged
\```

### Check Status Again
\```bash
git status # Lists changes ready to be committed
\```

### Pull Latest Changes
\```bash
git pull # Pulls the latest changes from the remote repository
\```