<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PEPPER 파일분석 사이트</title>
<link href="./css/bootstrap.min.css" rel="stylesheet">
<link href="./css/custom.css" rel="stylesheet">
<script
	src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.2/jquery.min.js"></script>
<script src="./js/bootstrap.min.js"></script>


</head>
<body>
	<div class="container">
		<div class="header">
			<nav>
				<ul class="nav nav-pills pull-right">
					<li role="presentation" class="active"><a href="#">Home</a></li>
					<li role="presentation"><a href="#">About</a></li>
					<li role="presentation"><a href="#">Contact</a></li>
				</ul>
			</nav>
			<h3 class="text-muted">PEPPER </h3>
		</div>

		<div class="jumbotron">
			<h1>파일 분석기 PEPPER v1.0</h1>
			<p class="lead">분석할 파일을 업로드 하세요</p>

			<form action="fileUpload.jsp" method="post"
				enctype="Multipart/form-data">
				<p>
					파일명 : <input class="btn btn-warning" type="file" name="fileName1" />

					<input class="btn btn-lg btn-success" type="submit" value="파일 업로드" />
				</p>
			</form>


		</div>


		<footer class="footer">
			<p>&copy; Company 2014</p>
		</footer>

	</div>
	<!-- /container -->

</body>
</html>
