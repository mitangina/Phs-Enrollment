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

if (isset($_SESSION['user_email'])) {
  $email = $_SESSION['user_email'];

  $sql = "SELECT e.lrn, e.fname, e.mname, e.lname, e.year_level, e.strand, e.age, i.pname, i.birthdate, i.gender, e.status
          FROM names e
          JOIN student_info i ON e.lrn = i.lrn
          WHERE e.email = '$email'"; 

  $result = mysqli_query($conn, $sql);
} else {
  echo "Email not found in session.";
  
  exit();
}  

?>

<!DOCTYPE html>
<html>
<head>
  <title>Student Profile</title>
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css" integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA==" crossorigin="anonymous" referrerpolicy="no-referrer" />

<style>
    body {
      font-family: sans-serif;
      height: 100vh;
      align-items: center;
      justify-content: center;
      display: flex;
      background-image: url("PSHS.jpeg");
      background-repeat: no-repeat;
      background-position: center;
      background-size: cover;
    }
    
    .student {
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
    
    h2 {
      border-bottom: 1px solid #ccc;
    }
   
    p {
      margin: 0;
      padding: 5px;
      font-size: 18px;
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
        
    .status {
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
    
  </style>
    
</head>

<body>
<div id="backButton" onclick="goBack()">
    <i class="fas fa-arrow-left"></i> Back
</div>

  <?php while($row = $result->fetch_assoc()) { ?>
    <div class="student">
    <p>LRN: <?php echo $row['lrn']; ?></p>

    <p>First Name: <?php echo $row['fname']; ?></p>

    <p>Middle Name:<?php echo $row['mname']; ?></p>

    <p>Last Name: <?php echo $row['lname']; ?></p>

    <p>Birthdate: <?php echo $row['birthdate']; ?></p>

    <p>Gender: <?php echo $row['gender']; ?></p>

    <p>Age: <?php echo $row['age']; ?></p>

    <p>Year Level: <?php echo $row['year_level']; ?></p>

    <p>Strand: <?php echo $row['strand']; ?></p>

    <p>Parents Name: <?php echo $row['pname']; ?></p>

    <!-- <hr> -->
    </div>
    <div class="status">
            <h2>Enrollment Status</h2>
            <?php
              if ($row['status'] === 'Approved') {
                  echo '<div style="background-color: #00AB41; border: 1px solid #c3e6cb; color: #fff; padding: 15px; margin-bottom: 15px;">
                            <strong>Success:</strong> Your enrollment form has been successfully approved.
                        </div>';
              } elseif ($row['status'] === 'Declined') {
                  echo '<div style="background-color: #ff0000; border: 1px solid #f5c6cb; color: #fff; padding: 15px; margin-bottom: 15px;">
                            <strong>Declined:</strong> Unfortunately, your enrollment form has been declined.
                        </div>';
              } else {
                  echo '<div style="background-color: #d6d8d9; border: 1px solid #c8cbcf; color: #000; padding: 15px; margin-bottom: 15px;">
                            <strong>Info:</strong> Your enrollment status is Pending.
                        </div>';
              }
            ?>
        </div>
        

  <?php } ?>  
  
  <form action="">

  </form>

    <script>
      function goBack() {
                window.location.href = "Dashboard.php";
            }
    </script>
</body>
</html>
