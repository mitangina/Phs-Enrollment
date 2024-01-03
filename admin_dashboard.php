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

$sql = "SELECT COUNT(*) AS num_students FROM names";
$result = $conn->query($sql);
$students_count = $result->fetch_assoc()['num_students'];

$sql = "SELECT COUNT(*) AS num_users FROM accounts"; 
$result = $conn->query($sql);
$users_count = $result->fetch_assoc()['num_users'];

?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ADMIN DASHBOARD</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css">
    <link rel="stylesheet" href="admin_dashboard.css">
    <style>

        body {
            color: #fff;
        }

        .dashboard-panel {
            margin-left: 15rem;
            display: flex;
            justify-content: center; /* Horizontally center the panel */
            background-color: #fff;
            padding: 20px;
            margin: 20px;
            border-radius: 5px;
            box-shadow: none; /* Remove the box shadow */
            border: none; /* Remove the border */
        }

        .dashboard-card {
            border: solid 2px #000;
            margin-left: 15rem;
            margin-top: 9rem;
            display: flex;
            flex-direction: column;
            align-items: center; /* Vertically center the content */
            background-color: #4fa2ed;
            width: 45%;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
            
        }

        .dashboard-card h2 {
            font-size: 24px;
            color: #fff;
        }

        .dashboard-card p {
            font-size: 18px;
            color: #fff;
        }
        nav {
            justify-content: space-between;
            background-color: #4fa2ed;
            box-shadow: 0 3px 20px rgba(0, 0, 0, 0.2);
            display: flex;
            padding: 5px 2rem 12px;
            border: solid .5px;
            border-color: #000000;
        }
        nav ul {
            align-items: center;
            display: flex;
            gap: 2rem;
            list-style: none;
        }

        nav ul li a {
            text-decoration: none;
            font-family: sans-serif;
            color: #000000;
            font-weight: 600;
            padding: 8px 0;
            transition: all;
            transition-duration: 300ms;
            border-bottom: 2px solid rgba(255, 68, 0, 0);
        }

        nav ul li a:hover {
            color: #ffffff;
            border-bottom: 2px solid #ffffff;
        }

        nav div img {
            width: 300px;
            border-radius: none;
        }
        input[type=text] {
        float: right;
        padding: 6px;
        border: none;
        margin-top: 8px;
        margin-right: 16px;
        font-size: 17px;
        }
        </style>
</head>

<body>
<!-- <nav>
		<div class="logo">
			<img src="LOGOS.png">
		</div>
				<ul>

					<li> <input type="text" placeholder="Search" > </li>

				</ul>
	</nav> -->
    <div class="wrapper">
        <?php include('sidebar.php');  ?>
        <div class="main_content">
            <div class="header">Welcome!! Have a nice day.</div>
           
        </div>
    </div>
    </div>

    <!-- Dashboard Panel -->
    <div class="dashboard-panel">
        <div class="dashboard-card">
            <h2><i class="fas fa-user"></i><br>Total Students</h2>
            <p><?php echo $students_count; ?></p> <!-- Replace with the actual total number of students -->
        </div>
        <div class="dashboard-card">
            <h2><i class="fas fa-address-card"></i><br>Total Users</h2>
            <p><?php echo $users_count; ?></p> <!-- Replace with the actual total number of users -->
        </div>
    </div>

    <!-- Rest of your content goes here -->
</div>

</div>
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>



</body>
</html>
