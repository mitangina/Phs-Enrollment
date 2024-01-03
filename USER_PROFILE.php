<?php
// Assume that the user is already logged in as an admin

// Check if the form is submitted for updating user details
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Include your database connection code here

    // Sanitize user input to prevent SQL injection
    $newUsername = mysqli_real_escape_string($db, $_POST['newUsername']);
    $newPassword = mysqli_real_escape_string($db, $_POST['newPassword']);

    // Update the user's details in the database
    $updateQuery = "UPDATE admin_table SET username = '$newUsername', password = '$newPassword' WHERE admin_id = $adminId";
    $result = mysqli_query($db, $updateQuery);

    if ($result) {
        $message = "User details updated successfully!";
    } else {
        $error = "Error updating user details: " . mysqli_error($db);
    }
}
?>

<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title></title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.1/css/all.min.css">
<style>
     nav {
            justify-content: space-between;
            background-color: #4fa2ed;
            box-shadow: 0 3px 20px rgba(0, 0, 0, 0.2);
            display: flex;
            padding: 15px 2rem 12px;
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
        nav div img {
            width: 300PX;
            border-radius: none;
        }

        nav ul li a:hover {
            color: #ffffff;
            border-bottom: 2px solid #ffffff;
        }
        input[type=text] {
        float: right;
        padding: 6px;
        border: none;
        margin-top: 8px;
        margin-right: 16px;
        font-size: 17px;
        }
        .profile-container {
      width: 500px;
      margin: 0 auto;
      padding: 20px;
      border: 2px solid #4fa2ed;
      border-radius: 3px;
    }

    .profile-container h1 {
      text-align: center;
    }

    .profile-container img {
      display: block;
      margin: 0 auto;
      width: 100px;
      height: 100px;
      border-radius: 50%;
    }

    .profile-container form {
      margin-top: 20px;
    }

    .profile-container input {
      width: 100%;
      padding: 10px;
      margin-bottom: 10px;
      border: 1px solid #ccc;
    }

    .profile-container button {
      width: 100%;
      background-color: #4caf50;
      color: white;
      padding: 10px;
      margin-bottom: 10px;
      border: none;
      cursor: pointer;
    }
        
</style>
</head>
<body>
  
<nav>
		<div class="logo">
        <a href="admin_dashboard.php" ><img src="LOGOS.png"></a>
		</div>
				<ul>

					<li> <input type="text" placeholder="Search" > </li>

				</ul>
	</nav>
<div class="wrapper">
        <?php include('sidebar.php'); // Include the sidebar content ?>
        <div class="main_content">
            <div class="header">Welcome!! Have a nice day.</div>
            <div class="container">
        <h2>Edit User Profile</h2>

        <?php
        // Display success or error messages
        if (isset($message)) {
            echo "<div class='success'>$message</div>";
        } elseif (isset($error)) {
            echo "<div class='error'>$error</div>";
        }
        ?>

    <div class="profile-container">
    <h1>User Profile</h1>

    <img src="https://placehold.it/100x100" alt="Profile picture">

    <form action="/USER_PROFILE" method="post">

    <input type="text" name="username" placeholder="Username">
 
    <input type="password" name="password" placeholder="Password">

      
    <input type="file" name="profile_picture">
    <button type="submit">Update Profile</button>
    </form>

      </div>
    </div>
  </div>
  </div>

</body>
</html>


    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
