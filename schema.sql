create table if not exists users(
	id integer primary key autoincrement,
	username text not null unique,
	password text not null
);

create table if not exists folders(
	id integer primary key autoincrement,
	user_id integer not null,
	name text not null
);


 create table if not exists memos(
	id integer primary key autoincrement,
	title text not null,
	contents text,
	done integer not null default 0,
	folder_id integer,
	owner_id integer not null,
	update_date text
);

create table if not exists memos_users(
	id integer primary key autoincrement,
	memo_id integer not null,
	user_id integer not null
);