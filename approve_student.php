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

if (isset($_GET['lrn'])) {
    $lrn = $_GET['lrn'];

    
    // Update the status to "Approved"
    $updateQuery = "UPDATE names SET status = 'Approved' WHERE lrn = $lrn";

    if ($conn->query($updateQuery) === TRUE) {
        $_SESSION['success_message'] = "Student approved successfully.";
    } else {
        $_SESSION['error_message'] = "Error approving student: " . $conn->error;
    }

    // Redirect back to the page where the approval was initiated
    header("Location: STUDENTS.php");
    exit();
} else {
    $_SESSION['error_message'] = "LRN not provided.";
    header("Location: STUDENTS.php");
    exit();
}

$conn->close();
?>
