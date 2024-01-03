<?php
session_start();

$servername = "localhost";
$username = "root";
$password = "";
$dbname = "phs_enrollment";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Check if student ID is provided in the request
if (isset($_GET['lrn'])) {
    $lrn = $_GET['lrn'];

    // Prepare and execute the SQL query to delete the student
    $updateQuery = "UPDATE names SET status = 'Declined' WHERE lrn = $lrn";

    if ($conn->query($updateQuery) === TRUE) {
        $_SESSION['success_message'] = "Student Declined successfully.";
    } else {
        $_SESSION['error_message'] = "Error Declining student: " . $conn->error;
    }

    // Redirect back to the page where the deletion was initiated
    header("Location: STUDENTS.php");
    exit();
} else {
    $_SESSION['error_message'] = "Student ID not provided.";
    header("Location: STUDENTS.php");
    exit();
}

$conn->close();
?>
