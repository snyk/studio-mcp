# Snyk Security At Inception

Project security best practices for AI-generated code:

- BEFORE declaring task complete: Run snyk_code_scan tool when a significant change has been made in first party code.
- This should only apply for Snyk-supported coding language
- If any security issues are found based on newly introduced or modified code or dependencies, attempt to fix the issues using the results context from Snyk.
- Rescan the code after fixing the issues to ensure that the issues were fixed and that there are no newly introduced issues.
- Repeat this process until no new issues are found.
