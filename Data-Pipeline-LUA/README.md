# Observo-LUA-Scripts

A repository of helpful Lua scripts designed to transform your Event Data within Observo.

> ⚠️ **IMPORTANT:** These scripts should be thoroughly tested before being deployed in a production environment. While I make every effort to keep these updated, you must verify that the logic applies correctly to your specific data structure.

## 🚀 How To Use These Scripts

Each script is designed to be as universal and flexible as possible. However, Lua transforms often require data to be in a specific "state" before the script can effectively target and apply changes to your events.

**Best Practices:**
1.  **Analyze your input:** Ensure your data fields match the variables expected by the script.
2.  **Verify:** Always use the **IN/OUT data preview** feature to verify that the output matches your expectations.
3.  **Test:** Run the script against a sample set before going live.

## 🐛 Reporting Issues & Requesting Help

If you encounter challenges, errors, or unexpected behavior, please create a new [GitHub Issue](https://github.com/blacknight659/observo-lua-scripts/issues).

To help me assist you quickly, please include the following details in your issue:

1.  **Sample Event:** A raw text sample of the event *before* transformation.
2.  **Current Lua Script:** A copy of the exact Lua code you used.
3.  **Desired End State:** A description (or sample) of what the data *should* look like.
4.  **The Issue:** A clear description of the error or the incorrect behavior you are seeing.
5.  **Screenshots:** (Optional) Images of the data preview or error logs are very helpful.

---
*Maintained by [blacknight659]*
