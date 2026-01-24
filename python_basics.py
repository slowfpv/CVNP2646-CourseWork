import time
#CVNP2646 - Week 2
#Task 3: Python Basics Demonstration
#This script shows variables, data types, prints, conditionals, loops, and comments.


# -----------------------------
# Variables + Data Types
# -----------------------------
name = "Bryan"               # string
age = 25                     # int
gpa = 3.5                    # float
is_student = True            # boolean
tools = ["Python", "Git", "JSON"]  # list

print("=== Variables & Data Types Demo ===")
print(f"Name (str): {name}")
time.sleep(0.5)
print(f"Age (int): {age}")
time.sleep(0.5)
print(f"GPA (float): {gpa}")
time.sleep(0.5)
print(f"Is Student (bool): {is_student}")
time.sleep(0.5)
print(f"Tools (list): {tools}")
time.sleep(0.5)

# -----------------------------1
# Conditional (if/else)
# -----------------------------
print("\n=== Conditional Demo ===")
if age >= 18:
    print(f"{name} is an adult (age >= 18).")
    time.sleep(0.5)
else:
    print(f"{name} is a minor (age < 18).")
    time.sleep(0.5)


# -----------------------------2
# Loop Demo (for loop)
# -----------------------------
print("\n=== Loop Demo (for loop) ===")
time.sleep(0.5)
for i, tool in enumerate(tools, start=1):
    print(f"{i}. {tool}")

# -----------------------------3
# Optional: while loop example
# -----------------------------
print("\n=== Loop Demo (while loop) ===")
countdown = 10
while countdown > 0:
    print(f"Countdown: {countdown}")
    time.sleep(1)
    countdown -= 1
print("Done!")
