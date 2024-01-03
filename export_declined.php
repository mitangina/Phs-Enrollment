<?php
// Similar to export_approved.php, modify based on your data retrieval logic

header('Content-Type: application/vnd.ms-excel');
header('Content-Disposition: attachment;filename="declined_students.xls"');
header('Cache-Control: max-age=0');

$servername = "localhost";
$username = "root";
$password = "";
$dbname = "phs_enrollment";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$sql = "SELECT * FROM names WHERE status = 'Declined'";
$result = $conn->query($sql);

echo '<table border="1">';
echo '<tr><th>LRN</th><th>Student Name</th><th>Age</th><th>Grade Level</th><th>Academic Track</th></tr>';

while ($row = $result->fetch_assoc()) {
    echo '<tr>';
    echo '<td style="mso-number-format:\'0\'">' . $row['lrn'] . '</td>';
    echo '<td>' . $row['fname'] . ' ' . $row['mname'] . ' ' . $row['lname'] . '</td>';
    echo '<td>' . $row['age'] . '</td>';
    echo '<td>' . $row['year_level'] . '</td>';
    echo '<td>' . $row['strand'] . '</td>';
    echo '</tr>';
}

echo '</table>';

$conn->close();
?>
