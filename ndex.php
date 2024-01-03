<?php
session_start(); // Start the session

// Database connection parameters
$hostname = "localhost";
$username = "root";
$password = "";
$database = "phs_enrollment";

// Establish a connection to the database
$conn = mysqli_connect($hostname, $username, $password, $database);

if (!$conn) {
    die("Failed to connect to the database: " . mysqli_connect_error());
}

$errors = [];


// Check if the email and password are provided in the POST request
if ($_SERVER["REQUEST_METHOD"] == "POST") {


    // Validate reCAPTCHA
    $recaptchaSecretKey = "6Ldx_AkpAAAAAESRHtPOXPx0Rkar8yTwsGpcV4Oz"; // Replace with your Secret Key
    $recaptchaResponse = $_POST['g-recaptcha-response'];

    $recaptchaUrl = "https://www.google.com/recaptcha/api/siteverify?secret=$recaptchaSecretKey&response=$recaptchaResponse";
    $recaptchaResult = json_decode(file_get_contents($recaptchaUrl));

    // if (!$recaptchaResult->success) {
    //     $errors[] = "reCAPTCHA verification failed. Please try again.";
    //     $_SESSION['message'] = "reCAPTCHA verification failed. Please try again.";
    // } else {
    //     // reCAPTCHA verification successful, continue with your existing login logic.
    
    // }
}

// Check if the email and password are provided in the POST request
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['email']) && isset($_POST['password'])) {
        // Sanitize user input
        $email = mysqli_real_escape_string($conn, $_POST['email']);
        $password = mysqli_real_escape_string($conn, $_POST['password']);

        // Check for specific email addresses to redirect to the admin dashboard
        $query = "SELECT email FROM accounts WHERE user_type = 'Admin'";
        $result = mysqli_query($conn, $query);
        
        if (!$result) {
            die("Query failed: " . mysqli_error($conn));
        }
        
        $adminEmails = [];
        while ($row = mysqli_fetch_assoc($result)) {
            $adminEmails[] = $row['email'];
        }
        
        // Check if the email is in the array of admin emails
        if (in_array($email, $adminEmails)) {
            // For admin email addresses, check the password directly
            $adminPassword = getPasswordForAdminEmail($email, $conn);
        
            if (password_verify($password, $adminPassword)) {
                // Redirect to the admin dashboard
                header("Location: admin_dashboard.php");
                exit();
            } else {
                // Incorrect password for admin email
                $errors[] = "Incorrect email or password";
                $_SESSION['message'] = "Incorrect email or password";
            }
        } else {
            // Query to check if the email exists in the "accounts" table
            $query = "SELECT * FROM accounts WHERE Email = '$email'";
            $result = mysqli_query($conn, $query);

            if (!$result) {
                die("Query failed: " . mysqli_error($conn));
            }

            if (mysqli_num_rows($result) == 0) {
                // Email does not exist in the database
                $errors[] = "Email does not exist";
                $_SESSION['message'] = "Email does not exist";
            } else {
                // Email exists, check the password
                $user = mysqli_fetch_assoc($result);
                $hashedPassword = $user['Password']; // Assuming you store hashed passwords in the database

                if (password_verify($password, $hashedPassword)) {
                    if ($user['verify'] == 0) {
                        // Account not yet verified
                        $errors[] = "Account not yet verified, please verify to log in";
                        $_SESSION['message'] = "Account not yet verified, please verify to log in";
                    } else {
                        // Redirect to the user's dashboard
                        $_SESSION['user_email'] = $email;  // Store user's email in session
                        header("Location: Dashboard.php");
                        exit();
                    }
                } else {
                    // Incorrect password for regular user
                    $errors[] = "Incorrect email or password";
                    $_SESSION['message'] = "Incorrect email or password";
                }
            }
        }
    } else {
        // Handle the case where email and password are not set in the POST request
        $errors[] = "Email and password are required";
        $_SESSION['message'] = "Email and password are required";
    }
}

function getPasswordForAdminEmail($email, $conn) {
    $query = "SELECT Password FROM accounts WHERE Email = '$email'";
    $result = mysqli_query($conn, $query);

    if (!$result) {
        die("Query failed: " . mysqli_error($conn));
    }

    $user = mysqli_fetch_assoc($result);

    return $user['Password'];
}   

mysqli_close($conn);
?>

<?php
$recaptchaSiteKey = ($_SERVER['HTTP_HOST'] === 'localhost') ? '6Ldx_AkpAAAAAESRHtPOXPx0Rkar8yTwsGpcV4Oz' : '6Ldx_AkpAAAAAA2cyNPX9rud9aRfExJ80zxfo-u7
';
?>
<?php
//Check for success message in the session
// if (isset($_SESSION['message'])) {
//     echo '<div class="error-block">';
//     echo '<p>' . $_SESSION['message'] . '</p>';
//     echo '</div>';

//     unset($_SESSION['message']);
// }

    if (isset($_SESSION['success_message'])) {
        $successMessage = $_SESSION['success_message'];
    
        // Clear the session variable
        unset($_SESSION['success_message']);
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">    
    <style>
        .error-block {
            background-color: #ff6666;
            color: white;
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 20px;
        }

        .input-append {
            position: relative;
        }

        i {
        position: absolute;
        right: 10px;
        top: 50%;
        transform: translateY(-50%);
        cursor: pointer;
        user-select: none;
        right: 4%;
        }

        .g-recaptcha {
            display: grid;
            place-items: center;
        }
        
    </style>
</head>

<body>

    <form method="POST" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
        <div class="login-container">
            <?php
            if (isset($_SESSION['message'])) {
                echo '<div class="error-block">';
                echo '<p>' . $_SESSION['message'] . '</p>';
                echo '</div>';
            
                unset($_SESSION['message']);
            }
            // if (!empty($errors)) {
            //     echo '<div class="error-block">';
            //     foreach ($errors as $errorMsg) {
            //         echo '<p>' . $errorMsg . '</p>';
            //     }
            //     echo '</div>';
            // }
            ?>
            <img src="images/LOGO.png">

            <h1>LOGIN</h1>

            <input type="text" name="email" placeholder="Username" required>
            <div class="input-append">
                <input type="password" name="password" placeholder="Password" required>
                <i class="far fa-eye"></i>
            </div>
            <div class="g-recaptcha" data-sitekey="<?php echo $recaptchaSiteKey; ?>"></div>

            <input type="hidden" name="recaptcha_response" id="recaptcha_response" required>
            <button type="submit" onclick="return validateForm()">Login</button> <br>
            <p> Don't have an account? <a href="Register.php">Register</a>
        </div>
    </form>

    <script src="https://www.recaptcha.net/recaptcha/api.js"></script>
    <script>
        const $password = document.querySelector('input[name="password"]');
        const $toggler = document.querySelector('input[name="password"] + i.fa-eye');
        

        const showHidePassword = () => {
            if ($password.type === 'password') {
                $password.setAttribute ('type', 'text');
                
            } else {
                $password.setAttribute ('type', 'password');
            }

            $toggler.classList.toggle('fa-eye');
            $toggler.classList.toggle('fa-eye-slash');

        };

        $toggler.addEventListener('click', showHidePassword);

          
    </script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script>
    function validateForm() {
        if (grecaptcha.getResponse().length === 0) {
            Swal.fire({
                icon: 'error',
                title: 'Oops...',
                text: 'Prove that you are not a Robot.',
            });
            return false;
        }
    }
    </script>
    <script>
            // Display SweetAlert with the success message
            Swal.fire({
                icon: 'success',
                title: 'Success',
                text: '<?php echo $successMessage; ?>',
                confirmButtonText: 'OK'
            }).then((result) => {
                if (result.isConfirmed) {
                    // Optionally redirect the user or perform other actions
                }
            });
        </script>

</body>
</html>
<?php
} else {
    // If no success message, display your regular HTML content
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">    
    <style>
        .error-block {
            background-color: #ff6666;
            color: white;
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 20px;
        }

        .input-append {
            position: relative;
        }

        i {
        position: absolute;
        right: 10px;
        top: 50%;
        transform: translateY(-50%);
        cursor: pointer;
        user-select: none;
        right: 4%;
        }

        .g-recaptcha {
            display: grid;
            place-items: center;
        }
        
    </style>
</head>

<body>

    <form method="POST" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
        <div class="login-container">
            <?php
            if (isset($_SESSION['message'])) {
                echo '<div class="error-block">';
                echo '<p>' . $_SESSION['message'] . '</p>';
                echo '</div>';
            
                unset($_SESSION['message']);
            }
            // if (!empty($errors)) {
            //     echo '<div class="error-block">';
            //     foreach ($errors as $errorMsg) {
            //         echo '<p>' . $errorMsg . '</p>';
            //     }
            //     echo '</div>';
            // }
            ?>
            <img src="images/LOGO.png">

            <h1>LOGIN</h1>

            <input type="text" name="email" placeholder="Username" required>
            <div class="input-append">
                <input type="password" name="password" placeholder="Password" required>
                <i class="far fa-eye"></i>
            </div>
            <div class="g-recaptcha" data-sitekey="<?php echo $recaptchaSiteKey; ?>"></div>

            <input type="hidden" name="recaptcha_response" id="recaptcha_response" required>
            <button type="submit" onclick="return validateForm()">Login</button> <br>
            <p> Don't have an account? <a href="Register.php">Register</a>
        </div>
    </form>

    <script src="https://www.recaptcha.net/recaptcha/api.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script>
        const $password = document.querySelector('input[name="password"]');
        const $toggler = document.querySelector('input[name="password"] + i.fa-eye');
        

        const showHidePassword = () => {
            if ($password.type === 'password') {
                $password.setAttribute ('type', 'text');
                
            } else {
                $password.setAttribute ('type', 'password');
            }

            $toggler.classList.toggle('fa-eye');
            $toggler.classList.toggle('fa-eye-slash');

        };

        $toggler.addEventListener('click', showHidePassword);

          
    </script>
    <script>
    function validateForm() {
        if (grecaptcha.getResponse().length === 0) {
            Swal.fire({
                icon: 'error',
                title: 'Oops...',
                text: 'Prove that you are not a Robot.',
            });
            return false;
        }
    }
    </script>

</body>
</html>
<?php
}
?>
