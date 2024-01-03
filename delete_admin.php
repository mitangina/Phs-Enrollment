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

if (isset($_GET['account_Id'])) {
    // Get the adminId from the $_GET parameters
    $adminId = $_GET['account_Id'];

    // Check if the adminId is a valid integer
    if (!is_numeric($adminId)) {
        $_SESSION['error_message'] = "Invalid admin ID.";
        header("Location: USERS.php");
        exit();
    }

    // Prepare and execute the SQL query to delete the admin user
    $deleteQuery = "DELETE FROM accounts WHERE id = $adminId";

    if ($conn->query($deleteQuery) === TRUE) {
        $_SESSION['success_message'] = "Admin user deleted successfully.";
    } else {
        $_SESSION['error_message'] = "Error deleting admin user: " . $conn->error;
    }

    // Redirect back to the page where the deletion was initiated
    header("Location: USERS.php");
    exit();
} else {
    $_SESSION['error_message'] = "Admin ID not provided.";
    header("Location: USERS.php");
    exit();
}

$conn->close();
?>
