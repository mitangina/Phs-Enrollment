<?php
session_start(); // Start the session

// Check if the user is logged in
if (!isset($_SESSION['user_email'])) {
    $_SESSION['message'] = "Please log in to access the Enrollment page";
    header("Location: ndex.php");
    exit();
}
$lrn = $_SESSION['lrn'];
?>

<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ENROLLMENT PROCESS</title>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <style>
        *{
            box-sizing: border-box;
        }
        body {
            min-height: 100vh;
            align-items: center;
            display: flex;
            justify-content: center;
            background-image: url("images/PSHS.jpeg");
            background-repeat: no-repeat;
            background-size: cover;
            overflow-y: auto;
        }

        form {
            width: 500px;
            border: 5px solid #ccc;
            padding: 30px;
            background: #fff;
            border-radius: 30px;
            border-color: #4fa2ed;
            background: rgba(225, 225, 225, 0.8);
            box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.5);
            overflow: hidden;
            backdrop-filter: blur(5px);
        }

        form div img {
            width: 80px;
            align-items: center;
            display: flex;
            border: 3px solid;
            border-color: #4fa2ed;
            border-radius: 50px;
            margin-left: auto;
            margin-right: auto;
        }

        .reg-cont input,textarea,select {
            background: rgba(225, 225, 225, 0.5);
            display: block;
            width: 95%;
            padding: 10px;
            margin: 10px auto;
            border-radius: 10px;
        }

        .hidden {
            display: none;
        }

        .reg-cont button {
            background-color: #4fa2ed;
            display: block;
            width: 95%;
            padding: 10px;
            margin: 10px auto;
            border-radius: 12px;
        }

        .new button {
            background-color: #4fa2ed;
            display: block;
            width: 50%;
            padding: 10px;
            margin: 10px auto;
            border-radius: 12px;

        }

        .requirementsSection .new {
            margin-top: 20px;
        }

        #backButton {
            position: fixed;
            top: 20px;
            left: 20px;
            cursor: pointer;
            font-size: 18px;
            padding: 10px;
            background-color: #4fa2ed;
            color: white;
            border: none;
            border-radius: 5px;
        }

        @media(max-width: 767px){
            .footer-col{
                width: 50%;
                margin-bottom: 30px;
            }
            }
            @media(max-width: 574px){
            .footer-col{
                width: 100%;
            }
        }

        .center {
            text-align: center;
        }

        .center h2 {
            margin-bottom: 10px; /* Add margin for better spacing */
        }

        .center p {
            margin-bottom: 20px; /* Add margin for better spacing */
        }
    </style>
</head>
<body>
<div id="backButton" onclick="goBack()">
    <i class="fas fa-arrow-left"></i> Back
</div>
    <form action="process_registration.php" method="POST" enctype="multipart/form-data" id="registrationForm">

    <div id="step1" class="reg-cont">
            <img src="images/LOGO.png">
            <div class="center">
            <h2>Welcome to the Enrollment Process</h2>
             <p>Follow the steps below to enroll in our program:</p>

            <h2>Registration Form (Part 1):</h2>
            <p>Put N/A if Not Available</p>
            </div>

            <label for="lrn">Learner's Reference Number (LRN):</label>
            <input type="text" id="lrn" placeholder="LRN" name="lrn" required><br>

            <label for="first_name">First Name:</label>
            <input type="text" id="fname" placeholder="First Name" name="first_name" required><br>

            <label for="middle_name">Middle Name:</label>
            <input type="text" id="mname" placeholder="Middle Name" name="middle_name"><br>

            <label for="last_name">Last Name:</label>
            <input type="text" id="lname" placeholder="Last Name" name="last_name" required><br>

            <label for="year_level">Year Level:</label>
            <select id="year_level" name="year_level" required>
                <option value="Grade 11">Grade 11</option>
                <option value="Grade 12">Grade 12</option>
            </select><br>

            <label for="strand">Select Strand:</label>
            <select id="strand" name="strand" required>
                <option value="ABM">ABM (Accountancy, Business, and Management)</option>
                <option value="STEM">STEM (Science, Technology, Engineering, and Mathematics)</option>
                <option value="HUMSS">HUMMS (Humanities and Social Sciences)</option>
            </select><br>

            <div id="error-message" style="color: red;"></div>
            <button id="nextButton1" type="button">Next</button>
        </div>

        <div id="step2" class="reg-cont hidden">
            <h2>Registration Form (Part 2):</h2>

            <label for="Parents">Parents Name / Guardians Name:</label>
            <input type="text" id="guardian" placeholder="Parent/Guardian Name" name="Parents/Guardian" required><br>

            <label for="age">Age:</label>
            <input type="number" id="age" placeholder="Age" name="age" required><br>

            <label for="gender">Gender:</label>
            <select id="gender" name="gender" required>
                <option value="male">Male</option>
                <option value="female">Female</option>
            </select><br>

            <label for="birthdate">Birthdate:</label>
            <input type="date" id="birthdate" name="birthdate" required><br>

            <button id="nextButton2" type="button">Next</button>
        </div>

        <div id="step3" class="reg-cont hidden">
            <h2>Registration Form (Part 3):</h2>
            <label for="house_street">House Number and Street:</label>
            <input type="text" id="house_street" placeholder="House Number and Street" name="house_street" required><br>

            <label for="barangay">Barangay:</label>
            <input type="text" id="barangay" placeholder="Baranggay" name="barangay" required><br>

            <label for="city">City or Municipality:</label>
            <input type="text" id="city" placeholder="City or Municipality" name="city" required><br>

            <label for="zip_code">Zip Code/Postal Code:</label>
            <input type="text" id="zip_code" placeholder="Zip code/Postal Code" name="zip_code" required><br>

            <button id="nextButton3" type="button">Next</button>
        </div>
        </div>
        <div id="step4" class="reg-cont hidden">
            <div class="new">
                <h2>Requirements:</h2>
                <ul>
                    <li>Original Report Card (Form 138)</li>
                    <li>Permanent Record (Form 137)</li>
                    <li>Certificate of Good Moral</li>
                    <li>NSO Birth Certificate (Photocopy)</li>
                    <li>Parents Consent Letter (If under 18, Please check your email)</li>
                </ul>

                <label for="file_upload">Upload Documents:</label>
                <input type="file" id="file_upload" name="file_upload" multiple><br>

                <button id="submitbutton" type="submit">Submit</button>
            </div>
        </div>
    </form>
    </div>   
    <script>
            document.addEventListener("DOMContentLoaded", function () {
                const form1Inputs = ["lrn", "first_name", "middle_name", "last_name", "year_level", "strand"];
                const form2Inputs = ["Parents/Guardian", "age", "gender", "birthdate"];
                const form3Inputs = ["house_street", "barangay", "city", "zip_code"];
                

                function validateForm(inputs) {
                    const formData = new FormData(document.getElementById('registrationForm'));

                    for (const input of inputs) {
                        const value = formData.get(input).trim();
                        if (value === "") {
                            alert("Please fill in all required fields before proceeding.");
                            return false;
                        }
                    }

                    // Additional condition to check if LRN contains exactly 12 numeric characters
                    const lrnValue = formData.get("lrn").trim();
                    const isLrnValid = /^\d{12}$/.test(lrnValue);

                    if (!isLrnValid) {
                        alert("LRN should be a 12-digit numeric value. Please enter a valid LRN.");
                        return false;
                    }

                    return true;
                }

                const step1 = document.getElementById("step1");
                const step2 = document.getElementById("step2");
                const step3 = document.getElementById("step3");
                const step4 = document.getElementById("step4");

                const nextButton1 = document.getElementById("nextButton1");
                const nextButton2 = document.getElementById("nextButton2");
                const nextButton3 = document.getElementById("nextButton3");

                nextButton1.addEventListener("click", function () {
                    if (validateForm(form1Inputs)) {
                        step1.style.display = "none";
                        step2.style.display = "block";
                    }
                });

                nextButton2.addEventListener("click", function () {
                    if (validateForm(form2Inputs)) {
                        step2.style.display = "none";
                        step3.style.display = "block";
                    }
                });

                nextButton3.addEventListener("click", function () {
                if (validateForm(form3Inputs)) {
                    step3.style.display = "none";
                    step4.style.display = "block";
                }
            });
         });

            function goBack() {
                window.location.href = "Dashboard.php";
            }
            
            
        </script>
</body>
</html>
