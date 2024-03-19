CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `passwordRequestTimes` int(1) DEFAULT 0,
  `jwt_token` varchar(255) DEFAULT NULL,
  `ip` varchar(255) NOT NULL,
  `app_name` varchar(255) NOT NULL,
  `app_version` varchar(255) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `jwt_token` (`jwt_token`) USING BTREE,
) ENGINE=InnoDB AUTO_INCREMENT=0 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `pins` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `value` int(4) NOT NULL,
  `email` varchar(100) NOT NULL,
  `requestTimes` int(1) NOT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  UNIQUE KEY `id` (`id`),
  FOREIGN KEY `email` REFERENCES `users` (`email`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=0 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
