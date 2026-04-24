# Manual cleanup to do once

The refactor was produced in a sandbox that could not delete a handful of
files it did not own. Please run these once on your local machine:

```powershell
cd C:\Apps\DEEPSecurity_v2.0
Remove-Item -Recurse -Force .\src
Remove-Item -Force .\frontend\src\components\ScanDashboard.jsx
```

That removes:

- An empty `src/` folder left behind when `src/App.jsx` was moved to `frontend/src/App.jsx`.
- A deprecated `ScanDashboard.jsx` that is no longer imported anywhere.

Neither blocks the app — they just look untidy in the tree. After running the
above you can delete this file too.

The `_legacy/` directory is intentional: it holds the old v2.0 sources next
to the new layout for diff / reference. Delete it when you're confident the
new code works for your workflow.
