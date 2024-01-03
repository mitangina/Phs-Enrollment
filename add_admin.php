<?php
session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['submit'])) {

    $email = $_POST['username'];
    $password = $_POST['password'];
    $verify = 1;

    $servername = "localhost";
    $username = "root";
    $dbpassword = "";
    $dbname = "phs_enrollment";

    $conn = new mysqli($servername, $username, $dbpassword, $dbname);

    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    $sql = "INSERT INTO accounts (user_type, email, password, created_at, verify) 
            VALUES ('Admin', '$email', '$hashedPassword', NOW(), '$verify')";

    if ($conn->query($sql) === TRUE) {
        $_SESSION['add'] = "Admin added successfully";
    } else {
        $_SESSION['add'] = "Error: " . $sql . "<br>" . $conn->error;
    }

    $conn->close();

    // Redirect to the form page to display the session message
    header("Location: USERS.php");
    exit();
}

if (isset($_SESSION['add'])) {
    echo $_SESSION['add'];
    unset($_SESSION['add']);
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Add Admin</title>
    <!-- Bootstrap CSS link -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>

<body>

    <div class="container mt-5">
        <form action="" method="POST">
            <div class="form-group row">
                <label for="username" class="col-sm-2 col-form-label">Email:</label>
                <div class="col-sm-10">
                    <input type="text" name="username" class="form-control" placeholder="Email">
                </div>
            </div>

            <div class="form-group row">
                <label for="password" class="col-sm-2 col-form-label">Password:</label>
                <div class="col-sm-10">
                    <input type="password" name="password" class="form-control" placeholder="Password">
                </div>
            </div>

            <div class="form-group row">
                <div class="col-sm-10 offset-sm-2">
                    <input type="submit" name="submit" value="Add Admin" class="btn btn-primary">
                </div>
            </div>
        </form>
    </div>


    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>

</html>
