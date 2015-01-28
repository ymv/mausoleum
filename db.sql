CREATE TABLE `file` (
	id	INTEGER UNSIGNED	AUTO_INCREMENT PRIMARY KEY,
	domain	VARCHAR(255)	NOT NULL,
	path	VARCHAR(1024)	NOT NULL,
	hash	CHAR(32),
	updated	INTEGER UNSIGNED,
	seen	INTEGER UNSIGNED	NOT NULL,
	size	BIGINT UNSIGNED,
	mime	VARCHAR(128),
	state	ENUM('active', 'deleted', 'history')	NOT NULL
);
CREATE TABLE file_segment (
	file_id	INTEGER UNSIGNED,
	i	INTEGER UNSIGNED,
	hash	CHAR(32)	NOT NULL,
	PRIMARY KEY (file_id, i)
);
CREATE TABLE slab (
	name	CHAR(36)	PRIMARY KEY,
	state	ENUM ('open', 'closed', 'busy')	NOT NULL
);
CREATE TABLE slab_segment (
	id	INTEGER UNSIGNED	AUTO_INCREMENT PRIMARY KEY,	
	slab	CHAR(36)	NOT NULL,
	offset	BIGINT UNSIGNED	NOT NULL,
	hash	CHAR(32)	NOT NULL
);
