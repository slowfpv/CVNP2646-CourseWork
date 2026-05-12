# Technical Reflection

## Project

VulnPriority Pro

## Student

Bryan Gonzalez

---

## 1. What technical problem did your project solve?

My capstone project solved the problem of organizing vulnerability or security event data into a more useful risk-based format. Instead of manually reviewing raw JSON data, the tool processes the input file and creates reports that make it easier to identify higher-risk items.

This is useful in cybersecurity because analysts often need to prioritize what should be reviewed first. A simple report that separates or highlights risk can save time and make the output easier to explain.

---

## 2. What was one technical challenge you faced, and how did you solve it?

One challenge I faced was getting the project structure and tests to work correctly. When a Python project has separate src, data, reports, and tests folders, imports can become confusing. I had to make sure the test files could access the functions in the main source code.

I solved this by checking the folder structure, making sure the source files were organized correctly, and running pytest until the tests passed. This helped me confirm that the core functions worked and that future changes would be easier to verify.

---

## 3. What is one important function or design decision in your project?

One important design decision was generating both a JSON report and a text summary report. The JSON report is useful because it is structured and could be used by another tool later. The text report is useful because it is easier for a person to read quickly.

This design made the project more realistic because cybersecurity tools often need to support both automation and human review.

---

## 4. How did you use AI responsibly during the project?

I used AI to help brainstorm, debug, and improve documentation. I did not accept every suggestion automatically. I reviewed the output, tested the code, and removed anything that did not match my project.

One example is that AI suggested advanced features such as dashboards, live feeds, or machine learning scoring. I rejected those as final project features because they were not actually implemented. Instead, I listed them as future improvements.

This helped me keep the project honest and accurate.

---

## 5. What would you improve if you had more time?

If I had more time, I would improve the project by adding more input formats, such as CSV. I would also add an HTML report so the results could be viewed in a browser. Another improvement would be stronger validation for bad or incomplete input data.

Long term, I would like to add a dashboard or connect the tool to real vulnerability feeds, but I would only add those after the current command-line version is fully stable.
