<?php
session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST") { 
    $user_type = "Admin";
    $created_at = "Date";
    $Verify = "verify";
    $_SESSION['Admin'] = $user_type;
    $_SESSION['Date'] = $created_at;
    $_SESSION['Verify'] = $Verify;
}

// Database connection details (replace with your actual credentials)
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "phs_enrollment";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// SQL query to select all columns from your admin_users table
$sql = "SELECT user_type, email, created_at FROM accounts WHERE user_type = 'Admin'";

// Execute the query
$result = $conn->query($sql);

// Fetch data into an associative array
$adminUsers = [];
if ($result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        $adminUsers[] = $row;
    }
}

// Close the database connection
$conn->close();
?>

<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>USERS</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.1/css/all.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/sweetalert2@11.4.8/dist/sweetalert2.min.css">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11.4.8/dist/sweetalert2.all.min.js"></script>
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

        span {
            color: #fff;
            bottom: 10px;
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
        
        table {
            margin: 2% 0 0 28%;
            width: 100%;
            border-collapse: collapse;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            border: solid 2px;
        }
   
        th, td {
            border: solid 2px #000000;
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }

        td.actions {
            align-items: center;
        }

        th {
            background-color: #4fa2ed;
            color: white;
        }

        tr:hover {
            background-color: #999da0;
        }
       
        .del-button {
            align-items: center;
            padding: 10px 20px;
            border-radius: 5px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            margin: 4px 2px;
            cursor: pointer;
            background-color: #ff0000;
            color: #fff;
            border: none;
            transition: background-color 0.3s ease-in-out;
            
        }
        .del-button:hover {
            background-color: #4fa2ed; 
            color: #fff; 
        }

        span {
            color: #fff;
        }

        .add_admin {
            margin: 3% 0 0 30%;
            padding: 10px 20px;
            cursor: pointer;
            background-color: #4fa2ed;
            color: #fff;
            border: none;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            border-radius: 5px;
            transition: background-color 0.3s ease-in-out;
        }
        .add_admin:hover {
            background-color: #90EE90; 
            color: #fff; 
        }
        
</style>
</head>
<body>
    
<!-- <nav>
		<div class="logo">
        <a href="admin_dashboard.php" ><img src="LOGOS.png"></a>
		</div>
				<ul>

					<li> <input type="text" placeholder="Search" > </li>

				</ul>
	</nav> -->
    <?php 
    if (isset($_SESSION['success_message'])) {
        echo "<script>
                Swal.fire({
                    title: 'Success',
                    text: '{$_SESSION['success_message']}',
                    icon: 'success',
                    confirmButtonText: 'Close'
                });
              </script>";
        unset($_SESSION['success_message']); // Clear the session variable
    }
    
    if (isset($_SESSION['error_message'])) {
        echo "<script>
                Swal.fire({
                    title: 'Error',
                    text: '{$_SESSION['error_message']}',
                    icon: 'error',
                    confirmButtonText: 'Close'
                });
              </script>";
        unset($_SESSION['error_message']); // Clear the session variable
    }
    ?>
    <div class="wrapper">
        <?php include('sidebar.php');  ?>
        <div class="main_content">
            <div class="header">Welcome!! Have a nice day.</div>
           
        </div>
    </div>
    </div>
        <form id="addAdminForm" method="post" action="add_admin.php">
        <button class="add_admin" type="submit"><span>Add Admin</span></button>
        </form>
        <table id="example" class="table table-striped table-bordered" style="width: 50rem;">
            <thead>
                <tr>
                    <?php
                    // Output table headers based on the database columns
                    if (!empty($adminUsers)) {
                        foreach ($adminUsers[0] as $columnName => $value) {
                            echo "<th>$columnName</th>";
                        }
                        echo "<th>Actions</th>";
                    }
                    ?>
                </tr>
            </thead>
            <tbody>
        <?php
        // Output table rows based on the database data
        foreach ($adminUsers as $adminUser) {
            echo "<tr>";
            foreach ($adminUser as $value) {
                echo "<td>$value</td>";
            }
            // Add buttons for each row
            echo '<td>
                        <button class="del-button delete-button"><a href="delete_admin.php"><span>Delete</span></a></button>
                  </td>';
            echo "</tr>";
        }
        ?>
    </tbody>
        </table>
    </div>
</div>
    

    </div>

</body>
</html>


    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
    const deleteButtons = document.querySelectorAll('.delete-button');

    deleteButtons.forEach(deleteButton => {
        deleteButton.addEventListener('click', () => {
            Swal.fire({
                title: 'Are you sure you want to delete this Admin?',
                text: 'This action cannot be undone.',
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#d33',
                cancelButtonColor: '#3085d6',
                confirmButtonText: 'Yes, delete it!',
                cancelButtonText: 'No, cancel',
            }).then((result) => {
                if (result.isConfirmed) {
                    // Get the admin ID or any unique identifier for the admin to be deleted
                    const adminId = deleteButton.getAttribute('data-admin-id');

                    // Make an AJAX request to the server to delete the admin
                    $.ajax({
                        url: 'delete_admin.php',
                        type: 'GET',
                        data: { Admin: adminId },
                        success: function (response) {
                            Swal.fire({
                                title: 'Admin Deleted!',
                                text: 'The Admin was successfully deleted.',
                                icon: 'success',
                                confirmButtonText: 'Close',
                            });

                            // Here you can add additional logic if needed
                        },
                        error: function () {
                            Swal.fire({
                                title: 'Error!',
                                text: 'An error occurred while processing your request.',
                                icon: 'error',
                                confirmButtonText: 'Close',
                            });
                        }
                    });
                }
            });
        });
    });
</script>
