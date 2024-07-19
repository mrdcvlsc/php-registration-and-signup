<?php
session_start();

// check if the file was accessed from a post request
if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    header('Location: form-login.php');
	exit;
}

// If the user is logged in redirect to the home page...
if (isset($_SESSION['loggedin'])) {
	header('Location: home.php');
	exit;
}

$DATABASE_HOST = getenv("DATABASE_HOST");
$DATABASE_USER = getenv("DATABASE_USER");
$DATABASE_PASS = getenv("DATABASE_PASS");
$DATABASE_NAME = getenv("DATABASE_NAME");

// try and connect to the database using the info above.
$con = mysqli_connect($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASS, $DATABASE_NAME);

if ( mysqli_connect_errno() ) {
	// If there is an error with the connection, stop the script and display the error.
	exit('Failed to connect to MySQL: ' . mysqli_connect_error());
}

// ============== basic form validation ============== 

// Now we check if the data from the login form was submitted, isset() will check if the data exists.
if ( !isset($_POST['username'], $_POST['password']) ) {
	// Could not get the data that should have been sent.
	exit('Please fill both the username and password fields!');
}

// Make sure the submitted login values are not empty.
if (empty($_POST['username']) || empty($_POST['password']) || empty($_POST['email'])) {
	// One or more values are empty.
	exit('Please complete the registration form');
}

// Prepare our SQL, preparing the SQL statement will prevent SQL injection.
if ($stmt = $con->prepare('SELECT id, password FROM accounts WHERE username = ?')) {
	// Bind parameters (s = string, i = int, b = blob, etc), in our case the username is a string so we use "s"
	$stmt->bind_param(
        // i	corresponding variable has type int
        // d	corresponding variable has type float
        // s	corresponding variable has type string
        // b	corresponding variable is a blob and will be sent in packets
        
        // if there are multiple arguments to be binded we can do something like 'ssid'
        // each character coresponds to the argument types in the specified order.
        's',

        htmlspecialchars($_POST['username'])
    );
	$stmt->execute();

	// Store the result so we can check if the account exists in the database.
	$stmt->store_result();

    if ($stmt->num_rows > 0) {
        $stmt->bind_result($id, $password);
        $stmt->fetch();
        // Account exists, now we verify the password.
        // Note: remember to use password_hash in your registration file to store the hashed passwords.
        if (password_verify(htmlspecialchars($_POST['password']), $password)) {
            // Verification success! User has logged-in!
            // Create sessions, so we know the user is logged in, they basically act like cookies but remember the data on the server.
            session_regenerate_id();
            $_SESSION['loggedin'] = TRUE;
            $_SESSION['name'] = $_POST['username'];
            $_SESSION['id'] = $id;
            
            header('Location: home.php');
        } else {
            // Incorrect password
            echo 'Incorrect username and/or password!';
        }
    } else {
        // Incorrect username
        echo 'Incorrect username and/or password!';
    }

	$stmt->close();
}
?>