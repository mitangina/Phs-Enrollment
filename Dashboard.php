<?php
session_start();
if (!isset($_SESSION['user_email'])) {
    $_SESSION['message'] = "Please log in to access the Dashboard";
    header("Location: ndex.php");
    exit();
}

if (isset($_POST['logout'])) {
    session_destroy();
    header("Location:ndex.php");
    exit();
}


?>

<!DOCTYPE html>
<html>
<head>
    <title>Online Enrollment System - Dashboard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link rel="stylesheet" type="text/css" href="dashboard.css">
    <style>
        .logged-in-block {
            background-color: #4CAF50; /* Green color, you can adjust it as needed */
            color: white;
            padding: 10px;
            margin-top: 10px;
            border-radius: 5px;
            text-align: center;
        }

        .user-email {
            font-weight: bold;
        }
    </style>
</head>
<body>  

<form method="post" action="">
    <label>
        <input type="checkbox">
        <div class="div toggle">
            <span class="span_top common"></span>
            <span class="span_middle common"></span>
            <span class="span_bottom common"></span>
        </div>

        <div class="slide">
                <h1>MENU</h1>
                <ul>
                    <li><a href="Student_Profile.php"><i class="fas fa-user"></i> Profile</a></li>
                    <li><a href="Enrollment.php"><i class="fas fa-mail-bulk"></i> Enrollment</a></li>
                    <div class="logged-in-block">
                    Logged in using <span class="user-email"><?php echo $_SESSION['user_email']; ?></span> <br>
                    </div>
                    <li>
                        <button class="log-out" type="submit" name="logout">Log Out</button>
                    </li>
                </ul>
                
                <!-- <div id="dark-mode-icon" title="Toggle dark mode/light mode">
                    <i class="fa-solid fa-toggle-on"></i>
                </div> -->
            </div>
    </label>
</form>   
    <img class="kosayo" src="back.jpg">
   
<section class="service-section" id="service">
<div class="contain">
    <h1 class="center">MISSION</h1> <br>
    <p class="center-text">The Makati City Government will be the model for world-class local governance: providing for the well - being of its citizenry through the delivery of the highest level of basic, social and economic services with breakthrough technologies sustanaible financing, and competent, responsible and professional servants. </p>
</div>
</section>
<section class="vision-section" id="service">
<div class="contain">
    <h1 class="center">VISION</h1> <br>
    <p class="center-text">Makati shall lead the Philippines into the 21st century: its global and national enterprises, leading the creation of a new, responsible and sustainable economy; its citizens, productive, empowered and God loving.</p>
</div>
</section>


    <footer class="footer">
        <div class="container">
            <div class="row">
                <div class="footer-col">
                    <h4>company</h4>
                    <ul>
                        <li><a href="index.html#about">about us</a></li>
                        <li><a href="index.html#service">our services</a></li>
                    </ul>
                </div>
                <div class="footer-col">
                    <h4>follow us</h4>
                    <div class="social-links">
                        <a href="#"><i class="fab fa-facebook-f"></i></a>
                        <a href="#"><i class="fab fa-twitter"></i></a>
                        <a href="#"><i class="fab fa-instagram"></i></a>
                        <a href="#"><i class="fab fa-linkedin-in"></i></a>
                    </div>
                </div>
            </div>
        </div>
   </footer>

   <script>
    let darkModeIcon = document.querySelector('#dark-mode-icon');
    let body = document.body;

    darkModeIcon.addEventListener('click', () => {
        body.classList.toggle('dark-mode');
    });
</script>


</body>
</html>
