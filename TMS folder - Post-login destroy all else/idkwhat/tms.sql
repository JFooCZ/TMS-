USE `managesys`;

CREATE TABLE `user` (
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `userstatus` boolean NOT NULL,
  `usergroups` varchar(255),
  `session` text,
  PRIMARY KEY (`username`),
  UNIQUE (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;

INSERT INTO `user` (`username`, `password`, `email`, `usergroups`, `userstatus`, `session`)
VALUES ('test', 'abc123!!', 'test@test.com', 'test@test.com', 1, 'hardcode@example1234567890qwertyuiopasdfghjklxzxcvbnm');
USE `managesys`;

INSERT INTO `user` (`username`, `password`, `email`, `usergroups`, `userstatus`, `session`)
VALUES ('testtwo', 'abc123!!', 'test2@test.com', 'testgroup', 1, 'hardcode@example1234567890qwertyuiopasdfghjklxzxcvbnm');
USE `managesys`;

CREATE TABLE `usergroups` (
  `usergroups` varchar(255) NOT NULL,
  PRIMARY KEY (`usergroups`)
);

INSERT INTO `usergroups` (`usergroups`)
VALUES ('dev'),
		    ('PL'),
        ('PM');


-- CREATE DATABASE IF NOT EXISTS `managesys` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;
-- USE `managesys`;

-- CREATE TABLE `user` (
--   `username` varchar(50) NOT NULL,
--   `usergroups` varchar(255),
--   `password` varchar(255) NOT NULL,
--   `email` varchar(255) NOT NULL,
--   `userstatus` boolean NOT NULL,
--   `session` text,
--   PRIMARY KEY (`username`),
--   UNIQUE (`email`)
-- ) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;

-- INSERT INTO `user` (`username`, `usergroups`, `password`, `email`, `userstatus`, `session`) VALUES ('test', 'user', 'test', 'test@test.com', 1, `hardcode@example1234567890qwertyuiopasdfghjklxzxcvbnm`)

-- CREATE TABLE `usergroup` (
--   `usergroups` varchar(255) NOT NULL,
--   PRIMARY KEY (`usergroups`)
-- );


-- /* alter user 'root'@'localhost' identified with mysql_native_password by 'admin'; 

-- execute this query in the tab if anything goes wrong about sql version or permission */

-- CREATE DATABASE IF NOT EXISTS `managesys` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;
-- USE `managesys`;

-- CREATE TABLE `user` (
--   `username` varchar(50) NOT NULL,
--   `usergroups` varchar(50) NOT NULL,
--   `password` varchar(255) NOT NULL,
--   `email` varchar(255) NOT NULL,
--   PRIMARY KEY (`username`),
--   UNIQUE (`email`)
-- ) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;

-- INSERT INTO `user` (`username`, `usergroups`, `password`, `email`) VALUES ('test', 'user', 'test', 'test@test.com')




-- CREATE DATABASE IF NOT EXISTS `managesys` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;