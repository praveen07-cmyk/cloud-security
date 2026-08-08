# LAPTOP1 USER FLOW REPORT

## Verification Status: PASS

## End-to-End Testing

### Administrator Flow: PASS
1. **Login**: Successful navigation to dashboard.
2. **Action Queue**: Able to view and open Analyst Actions.
3. **Investigation**: Incident timelines, MITRE ATT&CK vectors, and CAIS explanations correctly correlate.
4. **Export**: PDF Generation triggers a download successfully.
5. **AWS Settings**: Modal allows Live connection testing and properly limits access to Admins.
6. **Logout**: Safely terminates the session.

### Security Analyst Flow: PASS
1. **Threat Center**: Filtering by 'Critical' successfully updates the view.
2. **Attack Graph/Replay**: Graph nodes display real data. Replay functions with Play/Pause controls.
3. **Action Restrictions**: Attempting to reach Admin Settings redirects with an access-denied flash message.

### Auditor Flow: PASS
1. **Compliance**: CIS mappings and AWS best-practice mappings are visible.
2. **Audit Logs**: Export functions are available.
3. **Write Actions Blocked**: Auditor roles are prevented from changing AWS settings or system configurations.

### Viewer Flow: PASS
1. **Dashboard**: Base metrics are visible.
2. **Restrictions**: Confirm that administrative buttons (Users, Settings, AWS toggles) are not rendered in the UI for Viewer roles.

## Notes
Role-Based Access Control logic on the backend tightly couples with Jinja conditional rendering on the frontend, resulting in seamless, secure user experiences.
