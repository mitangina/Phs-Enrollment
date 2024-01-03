<?php
session_start();

// Check if the user is logged in
if (!isset($_SESSION['user_email'])) {
    exit();
}

// Fetch the user_email from the session
$user_email = $_SESSION['user_email'];

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require 'vendor/autoload.php';

$hostname = "localhost";
$username = "root";
$password = "";
$database = "phs_enrollment";

$conn = new mysqli($hostname, $username, $password, $database);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Check if the form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Extract data from the first form
    $lrn = $_POST["lrn"];
    $fname = $_POST["first_name"];
    $mname = $_POST["middle_name"];
    $lname = $_POST["last_name"];
    $year_level = $_POST["year_level"];
    $strand = $_POST["strand"];

    // Validate LRN
    if (!is_numeric($lrn) || strlen($lrn) != 12 || !ctype_digit($lrn)) {
        // LRN should be a 12-digit number
        echo "Invalid LRN. Please enter a 12-digit numeric value.";
        // You may redirect or handle the error as needed
        exit();
    }

    // Insert data into the 'names' table using prepared statement
    $query1 = "INSERT INTO names (lrn, fname, mname, lname, year_level, strand)
            VALUES (?, ?, ?, ?, ?, ?)";

    $stmt1 = $conn->prepare($query1);
    $stmt1->bind_param("ssssss", $lrn, $fname, $mname, $lname, $year_level, $strand);
    $stmt1->execute();
    $stmt1->close();

    // Extract data from the second form
    $pname = $_POST["Parents/Guardian"];
    $birthdate = $_POST["birthdate"];
    $gender = $_POST["gender"];
    $age = $_POST["age"];

    // Validate Age
    if (!is_numeric($age) || $age < 0 || $age > 150) {
        // Age should be a positive numeric value
        echo "Invalid Age. Please enter a valid age.";
        // You may redirect or handle the error as needed
        exit();
    }

    // Insert data into the 'student_info' table using prepared statement
    $query2 = "INSERT INTO student_info (lrn, pname, birthdate, gender, age)
            VALUES (?, ?, ?, ?, ?)";

    $stmt2 = $conn->prepare($query2);
    $stmt2->bind_param("sssss", $lrn, $pname, $birthdate, $gender, $age);
    $stmt2->execute();
    $stmt2->close();

    // Check age and send email if age is 17 or below
    if ($age <= 17) {
        // Fetch user's email from the database
        $email_query = "SELECT email FROM accounts WHERE email = ?";
        $stmt_email = $conn->prepare($email_query);
        $stmt_email->bind_param("s", $user_email);
        $stmt_email->execute();
        $stmt_email->bind_result($user_email);

        // Create a new PHPMailer instance
        $phpmailer = new PHPMailer;

        // Set up your SMTP configuration
        $phpmailer->isSMTP();
        $phpmailer->Host       = 'smtp.gmail.com';
        $phpmailer->SMTPAuth   = true;
        $phpmailer->Username   = 'mit703843@gmail.com';
        $phpmailer->Password   = 'cznsikanzkvwpldk';
        $phpmailer->SMTPSecure = 'tls';
        $phpmailer->Port       = 587;

        // Recipients
        $phpmailer->setFrom('from@example.com', 'Parents Consent Form');
        $phpmailer->addAddress($user_email);
        $phpmailer->addReplyTo('info@example.com', 'Information');

        // Content
        $phpmailer->isHTML(true);
        $phpmailer->Subject = 'Pitogo Senior High School Parents Consent Form';
        $phpmailer->Body    = "Include this to the forms that you will pass on Pitogo Senior High School Enrollment.
        Also include this if you're going to pass the documents to the school. Here's the link: https://docs.google.com/document/d/1f2FvFE8gsY0Aq8reshjHtXRbEZuoeoOu/edit";
        $phpmailer->AltBody = 'This is the body in plain text for non-HTML mail clients';

        // Send the email
        try {
            $phpmailer->send();
            echo 'Email sent!';
        } catch (Exception $e) {
            echo 'Mailer Error: ' . $e->getMessage();
        }

        $stmt_email->close();
    } else {
        // Handle the case where fetching email failed
        echo "Failed to fetch email from the database.";
    }

    // Extract data from the third form
    $house_street = $_POST["house_street"];
    $barangay = $_POST["barangay"];
    $city = $_POST["city"];
    $zip_code = $_POST["zip_code"];

    // Insert data into the 'address' table using prepared statement
    $query3 = "INSERT INTO address (lrn, house_street, barangay, city, zip_code)
        VALUES (?, ?, ?, ?, ?)";

    $stmt3 = $conn->prepare($query3);
    $stmt3->bind_param("sssss", $lrn, $house_street, $barangay, $city, $zip_code);
    $stmt3->execute();
    $stmt3->close();

    $allowed_file_types = ['application/pdf'];
$upload_directory = "PHS FILES";

if (!file_exists($upload_directory)) {
    mkdir($upload_directory, 0777, true);
}

if ($_FILES["file_upload"]["error"] == 0) {
    $file_name = $_FILES["file_upload"]["name"];
    $file_tmp = $_FILES["file_upload"]["tmp_name"];
    $file_type = $_FILES["file_upload"]["type"];
    $file_size = $_FILES["file_upload"]["size"];

    // Check if the file type is PDF
    if (!in_array($file_type, $allowed_file_types)) {
        echo "Invalid file type. Please upload a PDF file.";
        exit();
    }

    move_uploaded_file($file_tmp, $upload_directory . DIRECTORY_SEPARATOR . $file_name);

    $full_file_path = $upload_directory . DIRECTORY_SEPARATOR . $file_name; // New variable

    $upload_date = date('Y-m-d H:i:s');

    $query4 = "INSERT INTO uploaded_files (lrn, file_name, file_path, upload_date)
    VALUES (?, ?, ?, ?)";

    $stmt4 = $conn->prepare($query4);

    // Pass the variables by reference in bind_param
    $stmt4->bind_param("ssss", $lrn, $file_name, $full_file_path, $upload_date);
    $stmt4->execute();
    $stmt4->close();
}

mysqli_close($conn);

// Redirect to a success page or back to the enrollment page
header("Location: Dashboard.php");
exit();
}
?>
