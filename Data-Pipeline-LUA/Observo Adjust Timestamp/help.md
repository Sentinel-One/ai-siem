🚀 Implementation Guide: Observo.ai Transformations
This directory contains both the raw Lua scripts and the pre-packaged JSON transforms for your data pipeline. Choose the method that best fits your workflow.

Option 1: The Lua Script (Manual Paste)
Use this if you want to quickly iterate on the logic or adjust settings (like timezones) directly in the UI.

Add a Transform: In your pipeline canvas, add a new Transform block.
Select Lua: Choose Lua Script from the function list.
Name It: Give it a descriptive name (e.g., Normalize_Timestamps_OCSF).
Paste Code: Copy the contents of the .lua file and paste it into the editor field.
Test: Click the Test button to validate the output against sample data.

ENJOY!

Option 2: The Complete Transform (JSON Import)
Use this to quickly deploy a pre-configured block that includes metadata and specific settings.
Download: Save the .json transform file to your local machine.
Import: Click Add Transform and select the Import option.
Upload File: Choose Import from Local System and select the file you just downloaded.
Test: Click Test to ensure the logic maps correctly to your current stream.

ENJOY!

⚙️ Configuration & Customization
The Lua scripts are designed to be "Config-First." Look for the comments (marked with --) at the top of the script:
Activating Code: Remove the -- to enable a feature (e.g., enabling a specific US Timezone offset).
Deactivating Code: Add -- to the start of a line to skip that logic.
Timezones: By default, most scripts are set to UTC. Follow the comments to adjust for EST, CST, MST, or PST.

🛠️ Support & Feedback
If you run into issues with K8s pod resources, parsing errors, or have ideas for optimization:

📫 Contact: justin.hamblin@sentinelone.com
