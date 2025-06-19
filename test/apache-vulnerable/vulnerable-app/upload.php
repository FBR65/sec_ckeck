<?php
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable File Upload</title>
</head>
<body>
    <h2>File Upload Test</h2>
    <form action="" method="post" enctype="multipart/form-data">
        <input type="file" name="fileToUpload" id="fileToUpload">
        <input type="submit" value="Upload File" name="submit">
    </form>

    <?php
    if (isset($_POST["submit"])) {
        $target_dir = "/tmp/uploads/";
        $target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
        
        // Vulnerable: No file type validation, no size limits
        if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
            echo "<p>The file ". htmlspecialchars(basename($_FILES["fileToUpload"]["name"])). " has been uploaded.</p>";
            echo "<p>File location: " . $target_file . "</p>";
        } else {
            echo "<p>Sorry, there was an error uploading your file.</p>";
        }
    }
    ?>
</body>
</html>