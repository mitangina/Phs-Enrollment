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

$studentsPerPage = 5;

// limit 5 per table
$current_page = isset($_GET['page']) ? $_GET['page'] : 1;

// Calculate the offset based on the current page
$offset = ($current_page - 1) * $studentsPerPage;

// Fetch student data from the database with LIMIT and OFFSET
$sql = "SELECT * FROM names LIMIT $studentsPerPage OFFSET $offset";
$result = $conn->query($sql);

// Fetch student data count for pagination
$sqlCount = "SELECT COUNT(*) AS total FROM names";
$resultCount = $conn->query($sqlCount);
$rowCount = $resultCount->fetch_assoc();
$totalStudents = $rowCount['total'];

// Process action if LRN and action parameters are present in the URL
if (isset($_GET['lrn']) && isset($_GET['action'])) {
    $lrn = $_GET['lrn'];
    $action = $_GET['action'];

    if ($action === 'approve') {
        // Example: Update the status to 'Approved'
        $updateSql = "UPDATE names SET status = 'Approved' WHERE lrn = $lrn";
        $conn->query($updateSql);
    } elseif ($action === 'delete') {
        // Example: Update the status to 'Declined'
        $updateSql = "UPDATE names SET status = 'Declined' WHERE lrn = $lrn";
        $conn->query($updateSql);
    }

    // Redirect back to the same page with the current page information
    header("Location: {$_SERVER['PHP_SELF']}?page=$current_page");
    exit();
}
?>


<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>STUDENTS</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.1/css/all.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/sweetalert2@11.4.8/dist/sweetalert2.min.css">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11.4.8/dist/sweetalert2.all.min.js"></script>
    <style>
    table {
        
        margin-top: 2%;
        margin-left: 18%;
        width: 15rem;
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

        th {
            background-color: #4fa2ed;
            color: white;
        }

        tr:hover {
            background-color: #999da0;
        }

        .app-button,
        .del-button {
            padding: 10px 20px;
            border-radius: 5px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            margin: 4px 2px;
            cursor: pointer;
        }

        .app-button {
            background-color: #4fa2ed;
            color: #fff;
            border: none;
        }

        .del-button {
            background-color: #ff0000;
            color: #fff;
            border: none;
        }


            span {
                color: #fff;
            }
        /* Add some styling to the action links */
        .action-links a {
            color: #ffffff;
            margin-right: 10px;
            text-decoration: none;
        }

        .action-links a:hover {
            text-decoration: underline;
        }
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
        
        .approved {
        color: #008000;
        }
	.declined {
	color: #ff0000;
	}
        
        .success-message {
        background-color: #d4edda;
        color: #155724; 
        padding: 10px;
        margin-bottom: 10px;
        border: 1px solid #c3e6cb; 
        border-radius: 5px; 
    }

    .error-message {
        background-color: #f8d7da; 
        color: #721c24; 
        padding: 10px;
        margin-bottom: 10px;
        border: 1px solid #f5c6cb; 
        border-radius: 5px; 
    }

    .prev-page, .next-page {
            margin-top: 2px;
            background-color: #4fa2ed;
            padding: 10px 20px;
            border-radius: 5px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            margin: 4px 2px;
            cursor: pointer;
    }
    .prev-page, .next-page span{
            color: #fff;
    }
    .export-approved, .export-declined {
            position: fixed;
            padding: 10px 20px;
            border-radius: 5px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            margin: 4px 2px;
            cursor: pointer;
            
    }
    .export-approved {
        left: 18%;
        top: 90%;
        background-color: #00AB41;
        color: #fff;
        border: none;
    }
    .export-declined {
        left: 36%;
        top: 90%;
        background-color: #ff0000;
        color: #fff;
        border: none;
    }

    .pages {
        margin-left: 18%;
    }

</style>
</head>
<body>
    
<!-- <nav>
		<div class="logo">
        <a href="admin_dashboard.php" ><img src="../IMAGES/LOGOS.png"></a>
		</div>
				<ul>

					<li> <input type="text" placeholder="Search" > </li>

				</ul>
</nav> -->
<div class="wrapper">
        <?php include('sidebar.php');  ?>
        <!-- <div class="main_content">
            <div class="header">Welcome!! Have a nice day.</div>
           
        </div> -->
    </div>
    </div>

    <div id="messages">
    <?php
    // Display success message
    if (isset($_SESSION['success_message'])) {
        echo "<script>
                Swal.fire({
                    icon: 'success',
                    title: 'Success',
                    text: '" . $_SESSION['success_message'] . "',
                    showConfirmButton: false,
                    timer: 2000
                });
              </script>";
        unset($_SESSION['success_message']);
    }

    // Display error message
    if (isset($_SESSION['error_message'])) {
        echo "<script>
                Swal.fire({
                    icon: 'error',
                    title: 'Error',
                    text: '" . $_SESSION['error_message'] . "'
                });
              </script>";
        unset($_SESSION['error_message']);
    }
    ?>
    </div>
   

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        <div class="div"></div>
        <table id="example" class="table table-striped table-bordered" style="width:80%"> 
    <tr>
        <th>LRN</th>
        <th>Student Name</th>
        <th>Age</th>
        <th>Grade Level</th>
        <th>Academic Track</th>
        <th>Status</th>
        <th>Actions</th>
        
    </tr>
    <?php
    // for loop to limit the display to 5 rows
    for ($i = 0; $i < $studentsPerPage && ($row = $result->fetch_assoc()); $i++) {
        echo "<tr>";
        echo "<td>" . $row['lrn'] . "</td>";
        echo "<td>" . $row['fname'] ." ". $row['mname']." ". $row['lname']. "</td>";
        echo "<td>" . $row['age'] . "</td>";
        echo "<td>" . $row['year_level'] . "</td>";
        echo "<td>" . $row['strand'] . "</td>";
        echo "<td class='" . strtolower($row['status']) . "'>" . $row['status'] . "</td>";
        echo "<td>
            <a class='app-button' href='javascript:void(0);' onclick='confirmAction(\"approve\", " . $row['lrn'] . ")'><span>Approve</span></a> |
            <a class='del-button' href='javascript:void(0);' onclick='confirmAction(\"delete\", " . $row['lrn'] . ")'><span>Decline</span></a>
        </td>";
        echo "</tr>";
    }
    ?>

</table>

<div class="pages">
        <?php if ($current_page > 1): ?>
            <button class="prev-page"><a href="?page=<?php echo $current_page - 1; ?>"><span>Previous</span></a></button>
        <?php endif; ?>

        <?php
        // Check if there are more pages
        $nextPage = $current_page + 1;
        $lastPage = ceil($totalStudents / $studentsPerPage);

        if ($nextPage <= $lastPage): ?>
            <button class="next-page"><a href="?page=<?php echo $nextPage; ?>"><span>Next</span></a></button>
        <?php endif; ?>
</div>

<button class="export-approved" id="export-approved-btn"><span>Export Approved Students</span></button>
<button class="export-declined" id="export-declined-btn"><span>Export Declined Students</span></button>

</body>
</html>


<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script>
        function confirmAction(action, lrn) {
            Swal.fire({
                title: 'Are you sure?',
                text: 'This action cannot be undone.',
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#d33',
                cancelButtonColor: '#3085d6',
                confirmButtonText: 'Yes',
                cancelButtonText: 'No'
            }).then((result) => {
                if (result.isConfirmed) {
                    // If the user confirms, proceed with the action
                    window.location.href = `?page=<?php echo $current_page; ?>&lrn=${lrn}&action=${action}`;
                }
            });
        }
    </script>
<script>
$(document).ready(function() {
    $("#export-approved-btn").click(function() {
        window.location.href = "export_approved.php";
    });

    $("#export-declined-btn").click(function() {
        window.location.href = "export_declined.php";
    });
});
</script>
