<?php
session_start();

// check if the file was accessed from a post request
if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    header('Location: form-register.php');
	exit;
}

// If the user is logged in don't allow new account registration
if (isset($_SESSION['loggedin'])) {
	exit('logout first to register a new account');
}


$DATABASE_HOST = getenv("DATABASE_HOST");
$DATABASE_USER = getenv("DATABASE_USER");
$DATABASE_PASS = getenv("DATABASE_PASS");
$DATABASE_NAME = getenv("DATABASE_NAME");

// Try and connect using the info above.
$con = mysqli_connect($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASS, $DATABASE_NAME);
if (mysqli_connect_errno()) {
	// If there is an error with the connection, stop the script and display the error.
	exit('Failed to connect to MySQL: ' . mysqli_connect_error());
}

// ============== basic form validation ============== 

// Now we check if the data was submitted, isset() function will check if the data exists.
if (!isset($_POST['username'], $_POST['password'], $_POST['email'])) {
	// Could not get the data that should have been sent.
	exit('Please complete the registration form!');
}

// Make sure the submitted registration values are not empty.
if (empty($_POST['username']) || empty($_POST['password']) || empty($_POST['email'])) {
	// One or more values are empty.
	exit('Please complete the registration form');
}

// ============== check if account already exist ============== 

// We need to check if the account with that username exists.
if ($stmt = $con->prepare('SELECT id, password FROM accounts WHERE username = ?')) {
    
    // ============== email validation ============== 
    if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
        exit('Email is not valid!');
    }

    // ============== username validation ============== 
    if (preg_match('/^[a-zA-Z0-9]+$/', $_POST['username']) == 0) {
        exit('Username is not valid!');
    }

    if (strlen($_POST['password']) > 20 || strlen($_POST['password']) < 5) {
        exit('Password must be between 5 and 20 characters long!');
    }

    // ============================================= 

	// Bind parameters (s = string, i = int, b = blob, etc), hash the password using the PHP password_hash function.
	$stmt->bind_param('s', $_POST['username']);
	$stmt->execute();
	$stmt->store_result();
	// Store the result so we can check if the account exists in the database.
	if ($stmt->num_rows > 0) {
		// Username already exists
		echo 'Username exists, please choose another!';
	} else {
		// Insert new account

        // Username doesn't exists, insert new account
        if ($stmt = $con->prepare('INSERT INTO accounts (username, password, email) VALUES (?, ?, ?)')) {
            
            // We do not want to expose passwords in our database, so hash the password and use password_verify when a user logs in.
            $password = password_hash(
                htmlspecialchars($_POST['password']),
                PASSWORD_DEFAULT
            );
            
            $stmt->bind_param(
                // i	corresponding variable has type int
                // d	corresponding variable has type float
                // s	corresponding variable has type string
                // b	corresponding variable is a blob and will be sent in packets
                
                // if there are multiple arguments to be binded we can do something like 'ssid'
                // each character coresponds to the argument types in the specified order.
                'sss',
                
                htmlspecialchars($_POST['username']),
                $password,
                htmlspecialchars($_POST['email'])
            );

            $stmt->execute();
            echo 'You have successfully registered! You can now login!';
        } else {
            // Something is wrong with the SQL statement, so you must check to make sure your accounts table exists with all three fields.
            echo 'Could not prepare statement!';
        }
	}
	$stmt->close();
} else {
	// Something is wrong with the SQL statement, so you must check to make sure your accounts table exists with all 3 fields.
	echo 'Could not prepare statement!';
}
$con->close();
?>
