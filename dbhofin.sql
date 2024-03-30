-- phpMyAdmin SQL Dump
-- version 5.2.0
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1:3306
-- Generation Time: Mar 30, 2024 at 03:43 AM
-- Server version: 8.0.31
-- PHP Version: 8.0.26

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `calendar`
--
CREATE DATABASE IF NOT EXISTS `calendar` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `calendar`;

-- --------------------------------------------------------

--
-- Table structure for table `schedule_list`
--

DROP TABLE IF EXISTS `schedule_list`;
CREATE TABLE IF NOT EXISTS `schedule_list` (
  `id` int NOT NULL AUTO_INCREMENT,
  `title` text NOT NULL,
  `description` text NOT NULL,
  `start_datetime` datetime NOT NULL,
  `end_datetime` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `schedule_list`
--

INSERT INTO `schedule_list` (`id`, `title`, `description`, `start_datetime`, `end_datetime`) VALUES
(1, 'asdasd', 'asdasdasd', '2024-03-21 08:53:00', '2024-03-21 01:53:00');
--
-- Database: `capstone`
--
CREATE DATABASE IF NOT EXISTS `capstone` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `capstone`;

-- --------------------------------------------------------

--
-- Table structure for table `activity_log`
--

DROP TABLE IF EXISTS `activity_log`;
CREATE TABLE IF NOT EXISTS `activity_log` (
  `activity_log_id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(100) NOT NULL,
  `date` varchar(100) NOT NULL,
  `action` varchar(100) NOT NULL,
  PRIMARY KEY (`activity_log_id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `activity_log`
--

INSERT INTO `activity_log` (`activity_log_id`, `username`, `date`, `action`) VALUES
(1, 'jkev', '2013-11-18 15:25:33', 'Add Subject RIZAL'),
(2, 'jkev', '2013-11-18 15:27:08', 'Edit Subject RIZAL'),
(3, '', '2013-11-18 15:30:46', 'Edit Subject IS 221'),
(4, '', '2013-11-18 15:31:12', 'Edit Subject IS 222'),
(5, '', '2013-11-18 15:31:24', 'Edit Subject IS 223'),
(6, '', '2013-11-18 15:31:34', 'Edit Subject IS 224'),
(7, '', '2013-11-18 15:31:54', 'Edit Subject IS 227'),
(8, '', '2013-11-18 15:32:37', 'Add Subject IS 411B'),
(9, '', '2013-11-18 15:34:54', 'Edit User jkev'),
(10, 'jkev', '2014-01-17 13:26:18', 'Add User admin'),
(11, 'admin', '2020-12-21 08:37:51', 'Add Subject 1234');

-- --------------------------------------------------------

--
-- Table structure for table `answer`
--

DROP TABLE IF EXISTS `answer`;
CREATE TABLE IF NOT EXISTS `answer` (
  `answer_id` int NOT NULL AUTO_INCREMENT,
  `quiz_question_id` int NOT NULL,
  `answer_text` varchar(100) NOT NULL,
  `choices` varchar(3) NOT NULL,
  PRIMARY KEY (`answer_id`)
) ENGINE=InnoDB AUTO_INCREMENT=93 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `answer`
--

INSERT INTO `answer` (`answer_id`, `quiz_question_id`, `answer_text`, `choices`) VALUES
(81, 32, 'john', 'A'),
(82, 32, 'smith', 'B'),
(83, 32, 'kevin', 'C'),
(84, 32, 'lorayna', 'D'),
(85, 34, 'Peso', 'A'),
(86, 34, 'PHP Hypertext', 'B'),
(87, 34, 'PHP Hypertext Preprosesor', 'C'),
(88, 34, 'Philippines', 'D'),
(89, 36, 'Right', 'A'),
(90, 36, 'Wrong', 'B'),
(91, 36, 'Wrong', 'C'),
(92, 36, 'Wrong', 'D');

-- --------------------------------------------------------

--
-- Table structure for table `assignment`
--

DROP TABLE IF EXISTS `assignment`;
CREATE TABLE IF NOT EXISTS `assignment` (
  `assignment_id` int NOT NULL AUTO_INCREMENT,
  `floc` varchar(300) NOT NULL,
  `fdatein` varchar(100) NOT NULL,
  `fdesc` varchar(100) NOT NULL,
  `teacher_id` int NOT NULL,
  `class_id` int NOT NULL,
  `fname` varchar(100) NOT NULL,
  PRIMARY KEY (`assignment_id`)
) ENGINE=InnoDB AUTO_INCREMENT=32 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `assignment`
--

INSERT INTO `assignment` (`assignment_id`, `floc`, `fdatein`, `fdesc`, `teacher_id`, `class_id`, `fname`) VALUES
(2, 'uploads/6843_File_Doc3.docx', '2013-10-11 01:24:32', 'fasfasf', 13, 36, 'Assignment number 1'),
(3, 'uploads/3617_File_login.mdb', '2013-10-28 19:35:28', 'q', 9, 80, 'q'),
(4, 'admin/uploads/7146_File_normalization.ppt', '2013-10-30 18:48:15', 'fsaf', 9, 95, 'fsaf'),
(5, 'admin/uploads/7784_File_ABSTRACT.docx', '2013-10-30 18:48:33', 'fsaf', 9, 95, 'dsaf'),
(6, 'admin/uploads/4536_File_ABSTRACT.docx', '2013-10-30 18:53:32', 'file', 9, 95, 'abstract'),
(10, 'admin/uploads/2209_File_598378_543547629007198_436971088_n.jpg', '2013-11-01 13:13:18', 'fsafasf', 9, 95, 'Assignment#2'),
(11, 'admin/uploads/1511_File_bootstrap.css', '2013-11-01 13:18:25', 'sdsa', 9, 95, 'css'),
(12, 'admin/uploads/4309_File_new  2.txt', '2013-11-17 23:21:46', 'test', 12, 145, 'test'),
(13, 'admin/uploads/5901_File_IS 112-Personal Productivity Using IS.doc', '2013-11-18 16:59:35', 'q', 12, 145, 'q'),
(15, 'admin/uploads/7077_File_win_boot_screen_16_9_by_medi_dadu-d4s7dc1.gif', '2013-11-25 10:38:45', 'afs', 18, 159, 'dasf'),
(16, 'admin/uploads/8470_File_win_boot_screen_16_9_by_medi_dadu-d4s7dc1.gif', '2013-11-25 10:39:19', 'test', 18, 160, 'assign1'),
(17, 'admin/uploads/2840_File_IMG_0698.jpg', '2013-11-25 15:53:20', 'q', 12, 161, 'q'),
(19, '', '2013-12-07 20:11:39', 'kevin test', 12, 162, ''),
(20, '', '2013-12-07 20:26:43', 'dasddsd', 12, 145, ''),
(21, '', '2013-12-07 20:26:43', 'dasddsd', 12, 162, ''),
(22, '', '2013-12-07 20:27:18', 'dasffsafsaf', 12, 162, ''),
(23, '', '2013-12-07 20:33:11', 'test', 12, 162, ''),
(24, 'admin/uploads/7053_File_win_boot_screen_16_9_by_medi_dadu-d4s7dc1.gif', '2013-12-07 20:39:05', 'kevin', 12, 0, 'kevin'),
(25, 'admin/uploads/2417_File_win_boot_screen_16_9_by_medi_dadu-d4s7dc1.gif', '2013-12-07 20:41:10', 'kevin', 12, 0, 'kevin'),
(26, 'admin/uploads/8095_File_win_boot_screen_16_9_by_medi_dadu-d4s7dc1.gif', '2013-12-07 20:43:25', 'kevin', 12, 0, 'kevin'),
(27, 'admin/uploads/4089_File_win_boot_screen_16_9_by_medi_dadu-d4s7dc1.gif', '2013-12-07 20:47:48', 'fasfafaf', 12, 0, 'fasf'),
(28, 'admin/uploads/2948_File_win_boot_screen_16_9_by_medi_dadu-d4s7dc1.gif', '2013-12-07 20:48:59', 'dasdasd', 12, 0, 'dasd'),
(29, 'admin/uploads/5971_File_win_boot_screen_16_9_by_medi_dadu-d4s7dc1.gif', '2013-12-07 20:50:47', 'dasdasd', 12, 0, 'dsad'),
(30, 'admin/uploads/6926_File_Resume.docx', '2014-02-13 11:27:59', 'q', 12, 167, 'q'),
(31, 'admin/uploads/8289_File_sample.pdf', '2020-12-21 09:56:48', 'asdasd', 9, 186, 'asdasd');

-- --------------------------------------------------------

--
-- Table structure for table `class`
--

DROP TABLE IF EXISTS `class`;
CREATE TABLE IF NOT EXISTS `class` (
  `class_id` int NOT NULL AUTO_INCREMENT,
  `class_name` varchar(100) NOT NULL,
  PRIMARY KEY (`class_id`)
) ENGINE=InnoDB AUTO_INCREMENT=25 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `class`
--

INSERT INTO `class` (`class_id`, `class_name`) VALUES
(7, 'BSIS-4A'),
(8, 'BSIS-4B'),
(12, 'BSIS-3A'),
(13, 'BSIS-3B'),
(14, 'BSIS-3C'),
(15, 'BSIS-2A'),
(16, 'BSIS-2B'),
(17, 'BSIS-2C'),
(18, 'BSIS-1A'),
(19, 'BSIS-1B'),
(20, 'BSIS-1C'),
(21, 'BSED-1A'),
(22, 'AB-1C'),
(23, 'BSIT-2B'),
(24, 'BSIT-1A');

-- --------------------------------------------------------

--
-- Table structure for table `class_quiz`
--

DROP TABLE IF EXISTS `class_quiz`;
CREATE TABLE IF NOT EXISTS `class_quiz` (
  `class_quiz_id` int NOT NULL AUTO_INCREMENT,
  `teacher_class_id` int NOT NULL,
  `quiz_time` int NOT NULL,
  `quiz_id` int NOT NULL,
  PRIMARY KEY (`class_quiz_id`)
) ENGINE=InnoDB AUTO_INCREMENT=18 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `class_quiz`
--

INSERT INTO `class_quiz` (`class_quiz_id`, `teacher_class_id`, `quiz_time`, `quiz_id`) VALUES
(13, 167, 3600, 3),
(14, 167, 3600, 3),
(15, 167, 1800, 3),
(16, 185, 900, 0),
(17, 186, 1800, 6);

-- --------------------------------------------------------

--
-- Table structure for table `class_subject_overview`
--

DROP TABLE IF EXISTS `class_subject_overview`;
CREATE TABLE IF NOT EXISTS `class_subject_overview` (
  `class_subject_overview_id` int NOT NULL AUTO_INCREMENT,
  `teacher_class_id` int NOT NULL,
  `content` varchar(10000) NOT NULL,
  PRIMARY KEY (`class_subject_overview_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `class_subject_overview`
--

INSERT INTO `class_subject_overview` (`class_subject_overview_id`, `teacher_class_id`, `content`) VALUES
(1, 167, '<p>Chapter&nbsp; 1</p>\r\n\r\n<p>Cha</p>\r\n');

-- --------------------------------------------------------

--
-- Table structure for table `content`
--

DROP TABLE IF EXISTS `content`;
CREATE TABLE IF NOT EXISTS `content` (
  `content_id` int NOT NULL AUTO_INCREMENT,
  `title` varchar(100) NOT NULL,
  `content` mediumtext NOT NULL,
  PRIMARY KEY (`content_id`)
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `content`
--

INSERT INTO `content` (`content_id`, `title`, `content`) VALUES
(1, 'Mission', '<pre>\r\n<span style=\"font-size:16px\"><strong>Mission</strong></span></pre>\r\n\r\n<p style=\"text-align:left\"><span style=\"font-family:arial,helvetica,sans-serif; font-size:medium\"><span style=\"font-size:large\">&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;</span></span>&nbsp; &nbsp;<span style=\"font-size:18px\"> &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; A leading institution in higher and continuing education commited to engage in quality instruction, development-oriented research sustinable lucrative economic enterprise, and responsive extension and training services through relevant academic programs to empower a human resource that responds effectively to challenges in life and acts as catalyst in the holistoic development of a humane society.&nbsp;</span></p>\r\n\r\n<p style=\"text-align:left\">&nbsp;</p>\r\n'),
(2, 'Vision', '<pre><span style=\"font-size: large;\"><strong>Vision</strong></span></pre>\r\n<p>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"font-size: large;\">&nbsp; Driven by its passion for continous improvement, the State College has to vigorously pursue distinction and proficieny in delivering its statutory functions to the Filipino people in the fields of education, business, agro-fishery, industrial, science and technology, through committed and competent human resource, guided by the beacon of innovation and productivity towards the heights of elevated status. </span><br /><br /></p>'),
(3, 'History', '<pre><span style=\"font-size: large;\">HISTORY &nbsp;</span> </pre>\r\n<p style=\"text-align: justify;\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Carlos Hilado Memorial State College, formerly Paglaum State College, is a public educational institution that aims to provide higher technological, professional and vocational instruction and training in science, agriculture and industrial fields as well as short term or vocational courses. It was Batas Pambansa Bilang 477 which integrated these three institutions of learning: the Negros Occidental College of Arts and Trades (NOCAT) in the Municipality of Talisay, Bacolod City National Trade School (BCNTS) in Alijis, Bacolod City, and the Negros Occidental Provincial Community College (NOPCC) in Bacolod City, into a tertiary state educational institution to be called Paglaum State College. Approved in 1983, the College Charter was implemented effective January 1, 1984, with Mr. Sulpicio P. Cartera as its President. The administrative seat of the first state college in Negros Occidental is located at the Talisay Campus which was originally established as Negros Occidental School of Arts and Trades (NOSAT) under R.A. 848, authored and sponsored by Hon. Carlos Hilado. It occupies a five-hectare land donated by the provincial government under Provincial Board Resolution No. 1163. The renaming of the college to Carlos Hilado Memorial State College was effected by virtue of House Bill No. 7707 authored by then Congressman Jose Carlos V. Lacson of the 3rd Congressional District, Province of Negros Occidental, and which finally became a law on May 5, 1994</p>\r\n<p style=\"text-align: justify;\">&nbsp;</p>\r\n<p style=\"text-align: justify;\">&nbsp;&nbsp;&nbsp; Talisay Campus. July 1, 1954 marked the formal opening of NOSAT with Mr. Francisco Apilado as its first Superintendent and Mr. Gil H. Tenefrancia as Principal. There were five (5) full time teachers, with an initial enrolment of eighty-nine (89) secondary and trade technical students. The shop courses were General Metal Works, Practical Electricity and Woodworking. The first classes were held temporarily at Talisay Elementary School while the shop buildings and classrooms were under construction. NOSAT was a recipient of FOA-PHILCUA aid in terms of technical books, equipment, tools and machinery. Alijis Campus. The Alijis Campus of the Carlos Hilado Memorial State College is situated in a 5-hectare lot located at Barangay Alijis, Bacolod City. The lot was a donation of the late Dr. Antonio Lizares. The school was formerly established as the Bacolod City National Trade School. The establishment of this trade technical institution is pursuant to R.A. 3886 in 1968, authored by the late Congressman Inocencio V. Ferrer of the second congressional district of the Province of Negros Occidental. Fortune Towne. The Fortune Towne Campus of the Carlos Hilado Memorial State College was originally situated in Negros Occidental High School (NOHS), Bacolod City on a lot owned by the Provincial Government under Provincial Board Resolution No. 91 series of 1970. The school was formerly established as the Negros Occidental Provincial Community College and formally opened on July 13, 1970 with the following course offerings: Bachelor of Arts, Technical Education and Bachelor of Commerce. The initial operation of the school started in July 13, 1970, with an initial enrolment of 209 students. Classes were first housed at the Negros Occidental High School while the first building was constructed. Then Governor Alfredo L. Montelibano spearheaded the first operation of the NOPCC along with the members of the Board of Trustees. In June 1995, the campus transferred to its new site in Fortune Towne, Bacolod City. Binalbagan Campus. On Nov. 24, 2000, the Negros Occidental School of Fisheries (NOSOF) in Binalbagan, Negros Occidental was integrated to the Carlos Hilado Memorial State College system as an external campus by virtue of Resolution No. 46 series of 2000.</p>'),
(4, 'Footer', '<p style=\"text-align:center\">CHMSC Online Learning Managenment System</p>\r\n\r\n<p style=\"text-align:center\">All Rights Reserved &reg;2013</p>\r\n'),
(5, 'Upcoming Events', '<pre>\r\nUP COMING EVENTS</pre>\r\n\r\n<p><strong>&gt;</strong> EXAM</p>\r\n\r\n<p><strong>&gt;</strong> INTERCAMPUS MEET</p>\r\n\r\n<p><strong>&gt;</strong> DEFENSE</p>\r\n\r\n<p><strong>&gt;</strong> ENROLLMENT</p>\r\n\r\n<p>&nbsp;</p>\r\n'),
(6, 'Title', '<p><span style=\"font-family:trebuchet ms,geneva\">CHMSC Online Learning Management System</span></p>\r\n'),
(7, 'News', '<pre>\r\n<span style=\"font-size:medium\"><em><strong>Recent News\r\n</strong></em></span></pre>\r\n\r\n<h2><span style=\"font-size:small\">Extension and Community Services</span></h2>\r\n\r\n<p style=\"text-align:justify\">This technology package was promoted by the College of Industrial Technology Unit is an index to offer Practical Skills and Livelihood Training Program particularly to the Ina ngTahanan of Tayabas, Barangay Zone 15, Talisay City, Negros Occidental</p>\r\n\r\n<p style=\"text-align:justify\">The respondent of this technology package were mostly &ldquo;ina&rdquo; or mothers in PurokTayabas. There were twenty mothers who responded to the call of training and enhancing their sewing skills. The beginners projects include an apron, elastics waist skirts, pillow-cover and t-shirt style top. Short sleeve blouses with buttonholes or contoured seaming are also some of the many projects introduced to the mothers. Based on the interview conducted after the culmination activity, the projects done contributed as a means of earning to the respondents.</p>\r\n\r\n<p style=\"text-align:justify\">&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; In support to the thrust of the government to improve the health status of neighboring barangays, the Faculty and Staff of CHMSC ECS Fortune Towne, Bacolod City, launched its Medical Mission in Patag, Silay City. It was conducted last March 2010, to address the health needs of the people. A medical consultation is given to the residents of SitioPatag to attend to their health related problems that may need medical treatment. Medical tablets for headache, flu, fever, antibiotics and others were availed by the residents.</p>\r\n\r\n<p style=\"text-align:justify\">&nbsp;</p>\r\n\r\n<p style=\"text-align:justify\">&nbsp;The BAYAN-ANIHAN is a Food Production Program with a battle cry of &ldquo;GOODBYE GUTOM&rdquo;, advocating its legacy &ldquo;Food on the Table for every Filipino Family&rdquo; through backyard gardening. NGO&rsquo;s, governmental organizations, private and public sectors, business sectors are the cooperating agencies that support and facilitate this project and Carlos Hilado Memorial State College (CHMSC) is one of the identified partner school. Being a member institution in advocating its thrust, the school through its Extension and Community Services had conducted capability training workshop along this program identifying two deputy coordinators and trainers last November 26,27 and 28, 2009, with the end in view of implementing the project all throughout the neighboring towns, provinces and regions to help address poverty in the country. Program beneficiaries were the selected families of GawadKalinga (GK) in Hope Village, Brgy. Cabatangan, Talisay City, with 120 families beneficiaries; GK FIAT Village in Silay City with 30 beneficiaries; Bonbon Dream Village brgy. E. Lopez, Silay City with 60 beneficiaries; and respectively Had. Teresita and Had. Carmen in Talisay City, Negros Occidental both with 60 member beneficiaries. This program was introduced to 30 household members with the end in view of alleviating the quality standards of their living.</p>\r\n\r\n<p style=\"text-align:justify\">&nbsp;</p>\r\n\r\n<p style=\"text-align:justify\">The extension &amp; Community Services of the College conducted a series of consultations and meetings with the different local government units to assess technology needs to determines potential products to be developed considering the abundance of raw materials in their respective areas and their product marketability. The project was released in November 2009 in six cities in the province of Negros Occidental, namely San Carlos, Sagay, Silay, Bago, Himamaylan and Sipalay and the Municipality of E. B Magalona</p>\r\n\r\n<p style=\"text-align:justify\">&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; The City of San Carlos focused on peanut and fish processing. Sagay and bago focused on meat processing, while Silay City on fish processing. The City of Himamaylan is on sardines, and in Sipalay focused on fish processing specially on their famous BARONGAY product. The municipality of E.B Magalona focused on bangus deboning.</p>\r\n\r\n<p style=\"text-align:justify\">&nbsp;</p>\r\n\r\n<p style=\"text-align:justify\">&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; The food technology instructors are tasked to provide the needed skills along with the TLDC Livelihood project that each City is embarking on while the local government units provide the training venue for the project and the training equipment and machine were provided by the Department of Science and Technology.</p>\r\n\r\n<p style=\"text-align:justify\">&nbsp;</p>\r\n'),
(8, 'Announcements', '<pre>\r\n<span style=\"font-size:medium\"><em><strong>Announcements</strong></em></span></pre>\r\n\r\n<p>Examination Period: October 9-11, 2013</p>\r\n\r\n<p>Semestrial Break: October 12- November 3, 2013</p>\r\n\r\n<p>FASKFJASKFAFASFMFAS</p>\r\n\r\n<p>GASGA</p>\r\n'),
(10, 'Calendar', '<pre style=\"text-align:center\">\r\n<span style=\"font-size:medium\"><strong>&nbsp;CALENDAR OF EVENT</strong></span></pre>\r\n\r\n<table align=\"center\" cellpadding=\"0\" cellspacing=\"0\" style=\"line-height:1.6em; margin-left:auto; margin-right:auto\">\r\n	<tbody>\r\n		<tr>\r\n			<td>\r\n			<p>First Semester &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;</p>\r\n			</td>\r\n			<td>\r\n			<p>June 10, 2013 to October 11, 2013&nbsp;</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>Semestral Break</p>\r\n			</td>\r\n			<td>\r\n			<p>Oct. 12, 2013 to November 3, 2013</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>Second Semester</p>\r\n			</td>\r\n			<td>\r\n			<p>Nov. 5, 2013 to March 27, 2014</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>Summer Break</p>\r\n			</td>\r\n			<td>\r\n			<p>March 27, 2014 to April 8, 2014</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>Summer</p>\r\n			</td>\r\n			<td>\r\n			<p>April 8 , 2014 to May 24, 2014</p>\r\n			</td>\r\n		</tr>\r\n	</tbody>\r\n</table>\r\n\r\n<p style=\"text-align:center\">&nbsp;</p>\r\n\r\n<table cellpadding=\"0\" cellspacing=\"0\" style=\"line-height:1.6em; margin-left:auto; margin-right:auto\">\r\n	<tbody>\r\n		<tr>\r\n			<td colspan=\"4\">\r\n			<p><strong>June 5, 2013 to October 11, 2013 &ndash; First Semester AY 2013-2014</strong></p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>June 4, 2013 &nbsp; &nbsp; &nbsp; &nbsp;</p>\r\n			</td>\r\n			<td>\r\n			<p>Orientation with the Parents of the College&nbsp;Freshmen</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>June 5</p>\r\n			</td>\r\n			<td>\r\n			<p>First Day of Service</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>June 5</p>\r\n			</td>\r\n			<td>\r\n			<p>College Personnel General Assembly</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>June 6,7</p>\r\n			</td>\r\n			<td>\r\n			<p>In-Service Training (Departmental)</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>June 10</p>\r\n			</td>\r\n			<td>\r\n			<p>First Day of Classes</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>June 14</p>\r\n			</td>\r\n			<td>\r\n			<p>Orientation with Students by College/Campus/Department</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>June 19,20,21</p>\r\n			</td>\r\n			<td>\r\n			<p>Branch/Campus Visit for Administrative / Academic/Accreditation/ Concerns</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td rowspan=\"2\">\r\n			<p>June</p>\r\n			</td>\r\n			<td>\r\n			<p>Club Organizations (By Discipline/Programs)</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>Student Affiliation/Induction Programs</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>July</p>\r\n			</td>\r\n			<td>\r\n			<p>Nutrition Month (Sponsor: Laboratory School)</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>July 11, 12</p>\r\n			</td>\r\n			<td>\r\n			<p>Long Tests</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>August&nbsp; 8, 9</p>\r\n			</td>\r\n			<td>\r\n			<p>Midterm Examinations</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>August 19</p>\r\n			</td>\r\n			<td>\r\n			<p>ArawngLahi</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>August 23</p>\r\n			</td>\r\n			<td>\r\n			<p>Submission of Grade Sheets for Midterm</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>August</p>\r\n			</td>\r\n			<td>\r\n			<p>Recognition Program (Dean&rsquo;s List)</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>August 26</p>\r\n			</td>\r\n			<td>\r\n			<p>National Heroes Day (Regular Holiday)</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>August 28, 29, 30</p>\r\n			</td>\r\n			<td>\r\n			<p>Sports and Cultural Meet</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>September 19,20</p>\r\n			</td>\r\n			<td>\r\n			<p>Long Tests</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>October 5</p>\r\n			</td>\r\n			<td>\r\n			<p>Teachers&rsquo; Day / World Teachers&rsquo; Day</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>October 10, 11</p>\r\n			</td>\r\n			<td>\r\n			<p>Final Examination</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>October 12</p>\r\n			</td>\r\n			<td>\r\n			<p>Semestral Break</p>\r\n			</td>\r\n		</tr>\r\n	</tbody>\r\n</table>\r\n\r\n<p style=\"text-align:center\">&nbsp;</p>\r\n\r\n<table cellpadding=\"0\" cellspacing=\"0\" style=\"margin-left:auto; margin-right:auto\">\r\n	<tbody>\r\n		<tr>\r\n			<td colspan=\"4\">\r\n			<p><strong>Nov. 4, 2013 to March 27, 2014 &ndash; Second Semester AY 2013-2014</strong></p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>November 4 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;</p>\r\n			</td>\r\n			<td>\r\n			<p>Start of Classes</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>November 19, 20, 21, 22</p>\r\n			</td>\r\n			<td>\r\n			<p>Intercampus Sports and Cultural Fest/College Week</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>December 5, 6</p>\r\n			</td>\r\n			<td>\r\n			<p>Long Tests</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>December 19,20</p>\r\n			</td>\r\n			<td>\r\n			<p>Thanksgiving Celebrations</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>December 21</p>\r\n			</td>\r\n			<td>\r\n			<p>Start of Christmas Vacation</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>December 25</p>\r\n			</td>\r\n			<td>\r\n			<p>Christmas Day (Regular Holiday)</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>December 30</p>\r\n			</td>\r\n			<td>\r\n			<p>Rizal Day (Regular Holiday)</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>January 6, 2014</p>\r\n			</td>\r\n			<td>\r\n			<p>Classes Resume</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>January 9, 10</p>\r\n			</td>\r\n			<td>\r\n			<p>Midterm Examinations</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>January 29</p>\r\n			</td>\r\n			<td>\r\n			<p>Submission of Grades Sheets for Midterm</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>February 13, 14</p>\r\n			</td>\r\n			<td>\r\n			<p>Long Tests</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>March 6, 7</p>\r\n			</td>\r\n			<td>\r\n			<p>Final Examinations (Graduating)</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>March 13, 14</p>\r\n			</td>\r\n			<td>\r\n			<p>Final Examinations (Non-Graduating)</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>March 17, 18, 19, 20, 21</p>\r\n			</td>\r\n			<td>\r\n			<p>Recognition / Graduation Rites</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>March 27</p>\r\n			</td>\r\n			<td>\r\n			<p>Last Day of Service for Faculty</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>June 5, 2014</p>\r\n			</td>\r\n			<td>\r\n			<p>First Day of Service for SY 2014-2015</p>\r\n			</td>\r\n		</tr>\r\n	</tbody>\r\n</table>\r\n\r\n<p style=\"text-align:center\">&nbsp;</p>\r\n\r\n<table border=\"1\" cellpadding=\"0\" cellspacing=\"0\" style=\"margin-left:auto; margin-right:auto\">\r\n	<tbody>\r\n		<tr>\r\n			<td colspan=\"2\">\r\n			<p><strong>FLAG RAISING CEREMONY-TALISAY CAMPUS</strong></p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>MONTHS &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;&nbsp;</p>\r\n			</td>\r\n			<td>\r\n			<p>UNIT-IN-CHARGE</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>June, Sept. and Dec. 2013, March 2014</p>\r\n			</td>\r\n			<td>\r\n			<p>COE</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>July and October 2013, Jan. 2014</p>\r\n			</td>\r\n			<td>\r\n			<p>SAS</p>\r\n			</td>\r\n		</tr>\r\n		<tr>\r\n			<td>\r\n			<p>August and November 2013, Feb. 2014</p>\r\n\r\n			<p>April and May 2014</p>\r\n			</td>\r\n			<td>\r\n			<p>CIT</p>\r\n\r\n			<p>GASS</p>\r\n			</td>\r\n		</tr>\r\n	</tbody>\r\n</table>\r\n'),
(11, 'Directories', '<div class=\"jsn-article-content\" style=\"text-align: left;\">\r\n<pre>\r\n<span style=\"font-size:medium\"><em><strong>DIRECTORIES</strong></em></span></pre>\r\n\r\n<ul>\r\n	<li>Lab School - 712-0848</li>\r\n	<li>Accounting - 495-5560</li>\r\n	<li>Presidents Office - 495-4064(telefax)</li>\r\n	<li>VPA/PME - 495-1635</li>\r\n	<li>Registrar Office - 495-4657(telefax)</li>\r\n	<li>Cashier - 712-7272</li>\r\n	<li>CIT - 712-0670</li>\r\n	<li>SAS/COE - 495-6017</li>\r\n	<li>BAC - 712-8404(telefax)</li>\r\n	<li>Records - 495-3470</li>\r\n	<li>Supply - 495-3767</li>\r\n	<li>Internet Lab - 712-6144/712-6459</li>\r\n	<li>COA - 495-5748</li>\r\n	<li>Guard House - 476-1600</li>\r\n	<li>HRM - 495-4996</li>\r\n	<li>Extension - 457-2819</li>\r\n	<li>Canteen - 495-5396</li>\r\n	<li>Research - 712-8464</li>\r\n	<li>Library - 495-5143</li>\r\n	<li>OSA - 495-1152</li>\r\n</ul>\r\n</div>\r\n'),
(12, 'president', '<p>It is my great pleasure and privilege to welcome you to CHMSC&rsquo;s official website. Accept my deep appreciation for continuously taking interest in CHMSC and its programs and activities.<br /> Recently, the challenges of the knowledge era of the 21st Century led me to think very deeply how educational institutions of higher learning must vigorously pursue relevant e<img style=\"float: left;\" src=\"images/president.jpg\" alt=\"\" />ducation to compete with and respond to the challenges of globalization. As an international fellow, I realized that in the face of this globalization and technological advancement, educational institutions are compelled to work extraordinary in educating the youths and enhancing their potentials for gainful employment and realization of their dreams to become effective citizens.<br /><br /> Honored and humbled to be given the opportunity for stewardship of this good College, I am fully aware that the goal is to make CHMSC as the center of excellence or development in various fields. The vision, CHMSC ExCELS: Excellence, Competence and Educational Leadership in Science and Technology is a profound battle cry for each member of CHMSC Community. A CHMSCian must be technologically and academically competent, socially mature, safety conscious with care for the environment, a good citizen and possesses high moral values. The way the College is being managed, the internal and the external culture of all stockholders, and the efforts for quality and excellence will result to the establishment of the good corporate image of the College. The hallmark is reflected as the image of the good institution.<br /><br /> The tasks at hand call for our full cooperation, support and active participation. Therefore, I urge everyone to help me in the crusade to <br /><br /></p>\r\n<p style=\"text-align: justify;\"><span style=\"line-height: 1.3em;\">Provide wider access to CHMSC programs;</span></p>\r\n<p style=\"text-align: justify;\"><span style=\"line-height: 1.3em;\">&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;* Harness the potentials of students thru effective teaching and learning methodologies and techniques;</span></p>\r\n<p style=\"text-align: justify;\"><span style=\"line-height: 1.3em;\">&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;* Enable CHMSC Environment for All through secure green campus;</span></p>\r\n<p style=\"text-align: justify;\"><span style=\"line-height: 1.3em;\">&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;* Advocate green movement, protect intellectual property and stimulate innovation;</span></p>\r\n<p style=\"text-align: justify;\"><span style=\"line-height: 1.3em;\">&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;* Promote lifelong learning;</span></p>\r\n<p style=\"text-align: justify;\"><span style=\"line-height: 1.3em;\">&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;* Conduct Research and Development for community and poverty alleviation;</span></p>\r\n<p style=\"text-align: justify;\"><span style=\"line-height: 1.3em;\">&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;* Share and disseminate knowledge through publication and extension outreach to communities; and</span></p>\r\n<p style=\"text-align: justify;\"><span style=\"line-height: 1.3em;\">&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;*Strengthen Institute-industry linkages and public-private partnership for mutual interest.</span></p>\r\n<p style=\"text-align: justify;\"><br /><span style=\"line-height: 1.3em; text-align: justify;\">Together, WE can make CHMSC</span></p>\r\n<p style=\"text-align: justify;\"><br /><span style=\"line-height: 1.3em;\">&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;*A model green institution for Human Resources Development, a builder of human resources in the knowledge era of the 21st Century;</span></p>\r\n<p style=\"text-align: justify;\"><span style=\"line-height: 1.3em;\">&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; *A center for curricular innovations and research especially in education, technology, engineering, ICT and entrepreneurship; and</span></p>\r\n<p style=\"text-align: justify;\"><span style=\"line-height: 1.3em;\">&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; *A Provider of quality graduates in professional and technological programs for industry and community.</span></p>\r\n<p style=\"text-align: justify;\"><br /><br /> Dear readers and guests, these are the challenges for every CHMSCian to hurdle and the dreams to realize. This website will be one of the connections with you as we ardently take each step. Feel free to visit often and be kept posted as we continue to work for discoveries and advancement that will bring benefits to the lives of the students, the community, and the world, as a whole.<br /><br /> Warmest welcome and I wish you well!</p>\r\n<p style=\"text-align: justify;\"><br /><br /></p>\r\n<p style=\"text-align: justify;\">RENATO M. SOROLLA, Ph.D.<br />SUC President II</p>'),
(13, 'motto', '<p><strong><span style=\"color:#FFF0F5\"><span style=\"font-family:arial,helvetica,sans-serif\">CHMSC EXCELS:</span></span></strong></p>\r\n\r\n<p><strong><span style=\"color:#FFF0F5\"><span style=\"font-family:arial,helvetica,sans-serif\">Excellence, Competence and Educational</span></span></strong></p>\r\n\r\n<p><strong><span style=\"color:#FFF0F5\"><span style=\"font-family:arial,helvetica,sans-serif\">Leadership in Science and Technology</span></span></strong></p>\r\n'),
(14, 'Campuses', '<pre>\r\n<span style=\"font-size:16px\"><strong>Campuses</strong></span></pre>\r\n\r\n<ul>\r\n	<li>Alijis Campus</li>\r\n	<li>Binalbagan Campus</li>\r\n	<li>Fortunetown Campus</li>\r\n	<li>Talisay Campus<br />\r\n	&nbsp;</li>\r\n</ul>\r\n');

-- --------------------------------------------------------

--
-- Table structure for table `department`
--

DROP TABLE IF EXISTS `department`;
CREATE TABLE IF NOT EXISTS `department` (
  `department_id` int NOT NULL AUTO_INCREMENT,
  `department_name` varchar(100) NOT NULL,
  `dean` varchar(100) NOT NULL,
  PRIMARY KEY (`department_id`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `department`
--

INSERT INTO `department` (`department_id`, `department_name`, `dean`) VALUES
(4, 'College of Industrial Technology', 'Dr. Antonio Deraja'),
(5, 'School of Arts and Science', 'DR.'),
(9, 'College of Education', 'null'),
(10, 'Sample Department', 'DR. John Smith');

-- --------------------------------------------------------

--
-- Table structure for table `event`
--

DROP TABLE IF EXISTS `event`;
CREATE TABLE IF NOT EXISTS `event` (
  `event_id` int NOT NULL AUTO_INCREMENT,
  `event_title` varchar(100) NOT NULL,
  `teacher_class_id` int NOT NULL,
  `date_start` varchar(100) NOT NULL,
  `date_end` varchar(100) NOT NULL,
  PRIMARY KEY (`event_id`)
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `event`
--

INSERT INTO `event` (`event_id`, `event_title`, `teacher_class_id`, `date_start`, `date_end`) VALUES
(12, ' 	  Orientation with the Parents of the College Freshmen', 0, '06/04/2013', '06/04/2013'),
(13, 'Start of Classes', 0, '11/04/2013', '11/04/2013'),
(14, 'Intercampus Sports and Cultural Fest/College Week', 0, '11/19/2013', '11/22/2013'),
(15, 'Long Test', 113, '12/05/2013', '12/06/2013'),
(16, 'Long Test', 0, '12/05/2013', '12/06/2013'),
(17, 'sdasf', 147, '11/16/2013', '11/16/2013'),
(18, 'Sample', 186, '12/22/2020', '12/24/2020');

-- --------------------------------------------------------

--
-- Table structure for table `files`
--

DROP TABLE IF EXISTS `files`;
CREATE TABLE IF NOT EXISTS `files` (
  `file_id` int NOT NULL AUTO_INCREMENT,
  `floc` varchar(500) NOT NULL,
  `fdatein` varchar(200) NOT NULL,
  `fdesc` varchar(100) NOT NULL,
  `teacher_id` int NOT NULL,
  `class_id` int NOT NULL,
  `fname` varchar(100) NOT NULL,
  `uploaded_by` varchar(100) NOT NULL,
  PRIMARY KEY (`file_id`)
) ENGINE=MyISAM AUTO_INCREMENT=142 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `files`
--

INSERT INTO `files` (`file_id`, `floc`, `fdatein`, `fdesc`, `teacher_id`, `class_id`, `fname`, `uploaded_by`) VALUES
(133, 'admin/uploads/7939_File_449E26DB.jpg', '2014-02-20 10:31:38', 'sas', 14, 177, 'sss', ''),
(132, 'admin/uploads/7939_File_449E26DB.jpg', '2014-02-20 10:29:53', 'sas', 14, 178, 'sss', ''),
(131, 'admin/uploads/7939_File_449E26DB.jpg', '2014-02-20 10:28:09', 'sas', 14, 12, 'sss', ''),
(129, 'admin/uploads/7939_File_449E26DB.jpg', '2014-02-20 10:12:38', 'sas', 0, 12, 'sss', ''),
(130, 'admin/uploads/7939_File_449E26DB.jpg', '2014-02-20 10:26:11', 'sas', 0, 12, 'sss', ''),
(128, 'admin/uploads/7614_File_1476273_644977475552481_2029187901_n.jpg', '2014-02-13 13:31:18', 'qwwqw', 12, 185, 'kevi', 'Ruby Mae Morante'),
(127, 'admin/uploads/1085_File_Resume.docx', '2014-02-13 12:53:09', 'q', 12, 183, 'q', 'Ruby Mae Morante'),
(126, 'admin/uploads/7895_File_PERU REPORT.pptx', '2014-02-13 12:35:42', 'chapter 1', 12, 182, 'chapter 1', 'Ruby Mae Morante'),
(125, 'admin/uploads/2658_File_kevin.docx', '2014-02-13 11:10:56', 'test', 12, 181, 'test', 'Ruby Mae Morante'),
(123, 'admin/uploads/4801_File_painting-02.jpg', '2013-12-11 12:02:46', 'jdkasjfd', 12, 163, 'Test', 'Ruby Mae Morante'),
(122, 'admin/uploads/3985_File_win_boot_screen_16_9_by_medi_dadu-d4s7dc1.gif', '2013-12-07 20:00:22', 'dasdasd', 12, 145, 'dasd', 'Ruby Mae Morante'),
(121, 'admin/uploads/7439_File_win_boot_screen_16_9_by_medi_dadu-d4s7dc1.gif', '2013-12-07 19:59:46', 'asdad', 12, 162, 'kevin', 'Ruby Mae Morante'),
(120, 'admin/uploads/7439_File_win_boot_screen_16_9_by_medi_dadu-d4s7dc1.gif', '2013-12-07 19:59:46', 'asdad', 12, 145, 'kevin', 'Ruby Mae Morante'),
(119, 'admin/uploads/3166_File_win_boot_screen_16_9_by_medi_dadu-d4s7dc1.gif', '2013-12-07 19:58:44', 'kevin', 12, 145, 'kevin', 'Ruby Mae Morante'),
(118, 'admin/uploads/4849_File_win_boot_screen_16_9_by_medi_dadu-d4s7dc1.gif', '2013-11-26 23:59:20', 'q', 0, 162, 'qq', 'StephanieVillanueva'),
(117, 'admin/uploads/9467_File_win_boot_screen_16_9_by_medi_dadu-d4s7dc1.gif', '2013-11-26 10:42:37', 'test', 0, 162, 'report group 1', 'MarrianneTumala'),
(116, 'admin/uploads/5990_File_win_boot_screen_16_9_by_medi_dadu-d4s7dc1.gif', '2013-11-26 02:51:24', 'w', 12, 162, 'w', 'Ruby Mae Morante'),
(115, 'admin/uploads/5990_File_win_boot_screen_16_9_by_medi_dadu-d4s7dc1.gif', '2013-11-26 02:51:24', 'w', 12, 145, 'w', 'Ruby Mae Morante'),
(138, 'admin/uploads/3952_File_sample.pdf', '2020-12-21 09:24:50', 'Sample', 9, 186, 'Sample', 'JomarPabuaya'),
(139, 'admin/uploads/3579_File_sample.pdf', '2020-12-21 09:38:22', 'adasd', 9, 186, '234234', 'JomarPabuaya'),
(140, 'admin/uploads/6898_File_sample.pdf', '2020-12-21 09:39:32', 'adasd', 9, 186, '234234', 'JomarPabuaya'),
(141, 'admin/uploads/9782_File_sample.pdf', '2020-12-21 09:40:28', 'adasd', 9, 186, '234234', 'JomarPabuaya');

-- --------------------------------------------------------

--
-- Table structure for table `message`
--

DROP TABLE IF EXISTS `message`;
CREATE TABLE IF NOT EXISTS `message` (
  `message_id` int NOT NULL AUTO_INCREMENT,
  `reciever_id` int NOT NULL,
  `content` varchar(200) NOT NULL,
  `date_sended` varchar(100) NOT NULL,
  `sender_id` int NOT NULL,
  `reciever_name` varchar(50) NOT NULL,
  `sender_name` varchar(200) NOT NULL,
  `message_status` varchar(100) NOT NULL,
  PRIMARY KEY (`message_id`)
) ENGINE=InnoDB AUTO_INCREMENT=30 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `message`
--

INSERT INTO `message` (`message_id`, `reciever_id`, `content`, `date_sended`, `sender_id`, `reciever_name`, `sender_name`, `message_status`) VALUES
(2, 11, 'fasf', '2013-11-13 13:15:47', 42, 'Aladin Cabrera', 'john kevin lorayna', ''),
(4, 71, 'bcjhbcjksdbckldj', '2013-11-25 15:59:13', 71, 'Noli Mendoza', 'Noli Mendoza', 'read'),
(17, 12, 'tst', '2013-12-01 23:38:40', 93, 'Ruby Mae  Morante', 'John Kevin  Lorayna', ''),
(19, 12, 'fasfaf', '2013-12-01 23:56:17', 93, 'Ruby Mae  Morante', 'John Kevin  Lorayna', ''),
(27, 93, 'fa', '2013-12-02 00:01:54', 12, 'John Kevin  Lorayna', 'Ruby Mae  Morante', ''),
(28, 136, 'Submit your classcard', '2014-02-13 13:35:21', 12, 'Jorgielyn Serfino', 'Ruby Mae  Morante', ''),
(29, 18, 'Test message', '2020-12-21 08:51:10', 9, 'Allan Dela Torre', 'Jomar Pabuaya', '');

-- --------------------------------------------------------

--
-- Table structure for table `message_sent`
--

DROP TABLE IF EXISTS `message_sent`;
CREATE TABLE IF NOT EXISTS `message_sent` (
  `message_sent_id` int NOT NULL AUTO_INCREMENT,
  `reciever_id` int NOT NULL,
  `content` varchar(200) NOT NULL,
  `date_sended` varchar(100) NOT NULL,
  `sender_id` int NOT NULL,
  `reciever_name` varchar(100) NOT NULL,
  `sender_name` varchar(100) NOT NULL,
  PRIMARY KEY (`message_sent_id`)
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `message_sent`
--

INSERT INTO `message_sent` (`message_sent_id`, `reciever_id`, `content`, `date_sended`, `sender_id`, `reciever_name`, `sender_name`) VALUES
(1, 42, 'sad', '2013-11-12 22:50:05', 42, 'john kevin lorayna', 'john kevin lorayna'),
(2, 11, 'fasf', '2013-11-13 13:15:47', 42, 'Aladin Cabrera', 'john kevin lorayna'),
(3, 12, 'bjhkcbkjsdnckldvls', '2013-11-25 15:58:55', 71, 'Ruby Mae  Morante', 'Noli Mendoza'),
(4, 71, 'bcjhbcjksdbckldj', '2013-11-25 15:59:13', 71, 'Noli Mendoza', 'Noli Mendoza'),
(5, 12, 'test', '2013-11-30 20:54:05', 93, 'Ruby Mae  Morante', 'John Kevin  Lorayna'),
(11, 12, 'tst', '2013-12-01 23:38:40', 93, 'Ruby Mae  Morante', 'John Kevin  Lorayna'),
(12, 12, 'fasfasf', '2013-12-01 23:49:13', 93, 'Ruby Mae  Morante', 'John Kevin  Lorayna'),
(13, 136, 'Submit your classcard', '2014-02-13 13:35:21', 12, 'Jorgielyn Serfino', 'Ruby Mae  Morante'),
(14, 18, 'Test message', '2020-12-21 08:51:10', 9, 'Allan Dela Torre', 'Jomar Pabuaya');

-- --------------------------------------------------------

--
-- Table structure for table `notification`
--

DROP TABLE IF EXISTS `notification`;
CREATE TABLE IF NOT EXISTS `notification` (
  `notification_id` int NOT NULL AUTO_INCREMENT,
  `teacher_class_id` int NOT NULL,
  `notification` varchar(100) NOT NULL,
  `date_of_notification` varchar(50) NOT NULL,
  `link` varchar(100) NOT NULL,
  PRIMARY KEY (`notification_id`)
) ENGINE=InnoDB AUTO_INCREMENT=24 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `notification`
--

INSERT INTO `notification` (`notification_id`, `teacher_class_id`, `notification`, `date_of_notification`, `link`) VALUES
(2, 0, 'Add Downloadable Materials file name <b>sss</b>', '2014-01-17 14:35:32', 'downloadable_student.php'),
(3, 167, 'Add Annoucements', '2014-01-17 14:36:32', 'announcements_student.php'),
(4, 0, 'Add Downloadable Materials file name <b>test</b>', '2014-02-13 11:10:56', 'downloadable_student.php'),
(5, 167, 'Add Assignment file name <b>q</b>', '2014-02-13 11:27:59', 'assignment_student.php'),
(6, 0, 'Add Downloadable Materials file name <b>chapter 1</b>', '2014-02-13 12:35:42', 'downloadable_student.php'),
(7, 0, 'Add Downloadable Materials file name <b>q</b>', '2014-02-13 12:53:09', 'downloadable_student.php'),
(8, 0, 'Add Downloadable Materials file name <b>kevi</b>', '2014-02-13 13:31:18', 'downloadable_student.php'),
(9, 185, 'Add Practice Quiz file', '2014-02-13 13:33:27', 'student_quiz_list.php'),
(10, 167, 'Add Annoucements', '2014-02-13 13:45:59', 'announcements_student.php'),
(11, 0, 'Add Downloadable Materials file name <b>q</b>', '2014-02-21 16:43:38', 'downloadable_student.php'),
(12, 0, 'Add Downloadable Materials file name <b>q</b>', '2014-02-21 16:46:18', 'downloadable_student.php'),
(13, 0, 'Add Downloadable Materials file name <b>q</b>', '2014-02-21 16:46:49', 'downloadable_student.php'),
(14, 0, 'Add Downloadable Materials file name <b>q</b>', '2014-02-21 16:52:30', 'downloadable_student.php'),
(15, 186, 'Add Downloadable Materials file name <b>Sample</b>', '2020-12-21 09:24:50', 'downloadable_student.php'),
(16, 0, 'Add Downloadable Materials file name <b>123</b>', '2020-12-21 09:31:40', 'downloadable_student.php'),
(17, 0, 'Add Downloadable Materials file name <b>234234</b>', '2020-12-21 09:36:27', 'downloadable_student.php'),
(18, 0, 'Add Downloadable Materials file name <b>234234</b>', '2020-12-21 09:38:22', 'downloadable_student.php'),
(19, 186, 'Add Downloadable Materials file name <b>234234</b>', '2020-12-21 09:39:32', 'downloadable_student.php'),
(20, 186, 'Add Downloadable Materials file name <b>234234</b>', '2020-12-21 09:40:28', 'downloadable_student.php'),
(21, 186, 'Add Assignment file name <b>asdasd</b>', '2020-12-21 09:56:48', 'assignment_student.php'),
(22, 186, 'Add Annoucements', '2020-12-21 09:59:00', 'announcements_student.php'),
(23, 186, 'Add Practice Quiz file', '2020-12-21 10:10:11', 'student_quiz_list.php');

-- --------------------------------------------------------

--
-- Table structure for table `notification_read`
--

DROP TABLE IF EXISTS `notification_read`;
CREATE TABLE IF NOT EXISTS `notification_read` (
  `notification_read_id` int NOT NULL AUTO_INCREMENT,
  `student_id` int NOT NULL,
  `student_read` varchar(50) NOT NULL,
  `notification_id` int NOT NULL,
  PRIMARY KEY (`notification_read_id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `notification_read`
--

INSERT INTO `notification_read` (`notification_read_id`, `student_id`, `student_read`, `notification_id`) VALUES
(1, 219, 'yes', 22),
(2, 219, 'yes', 21),
(3, 219, 'yes', 20),
(4, 219, 'yes', 19),
(5, 219, 'yes', 15);

-- --------------------------------------------------------

--
-- Table structure for table `notification_read_teacher`
--

DROP TABLE IF EXISTS `notification_read_teacher`;
CREATE TABLE IF NOT EXISTS `notification_read_teacher` (
  `notification_read_teacher_id` int NOT NULL AUTO_INCREMENT,
  `teacher_id` int NOT NULL,
  `student_read` varchar(100) NOT NULL,
  `notification_id` int NOT NULL,
  PRIMARY KEY (`notification_read_teacher_id`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `notification_read_teacher`
--

INSERT INTO `notification_read_teacher` (`notification_read_teacher_id`, `teacher_id`, `student_read`, `notification_id`) VALUES
(1, 12, 'yes', 14),
(2, 12, 'yes', 13),
(3, 12, 'yes', 12),
(4, 12, 'yes', 11),
(5, 12, 'yes', 10),
(6, 12, 'yes', 9),
(7, 12, 'yes', 8),
(8, 12, 'yes', 7);

-- --------------------------------------------------------

--
-- Table structure for table `question_type`
--

DROP TABLE IF EXISTS `question_type`;
CREATE TABLE IF NOT EXISTS `question_type` (
  `question_type_id` int NOT NULL,
  `question_type` varchar(150) NOT NULL,
  PRIMARY KEY (`question_type_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `question_type`
--

INSERT INTO `question_type` (`question_type_id`, `question_type`) VALUES
(1, 'Multiple Choice'),
(2, 'True or False');

-- --------------------------------------------------------

--
-- Table structure for table `quiz`
--

DROP TABLE IF EXISTS `quiz`;
CREATE TABLE IF NOT EXISTS `quiz` (
  `quiz_id` int NOT NULL AUTO_INCREMENT,
  `quiz_title` varchar(50) NOT NULL,
  `quiz_description` varchar(100) NOT NULL,
  `date_added` varchar(100) NOT NULL,
  `teacher_id` int NOT NULL,
  PRIMARY KEY (`quiz_id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `quiz`
--

INSERT INTO `quiz` (`quiz_id`, `quiz_title`, `quiz_description`, `date_added`, `teacher_id`) VALUES
(3, 'Sample Test', 'Test', '2013-12-03 23:01:56', 12),
(4, 'Chapter 1', 'topics', '2013-12-13 01:51:02', 14),
(5, 'test3', '123', '2014-01-16 04:12:07', 12),
(6, 'Sample Quiz', 'Sample 101', '2020-12-21 10:04:11', 9);

-- --------------------------------------------------------

--
-- Table structure for table `quiz_question`
--

DROP TABLE IF EXISTS `quiz_question`;
CREATE TABLE IF NOT EXISTS `quiz_question` (
  `quiz_question_id` int NOT NULL AUTO_INCREMENT,
  `quiz_id` int NOT NULL,
  `question_text` varchar(100) NOT NULL,
  `question_type_id` int NOT NULL,
  `points` int NOT NULL,
  `date_added` varchar(100) NOT NULL,
  `answer` varchar(100) NOT NULL,
  PRIMARY KEY (`quiz_question_id`)
) ENGINE=InnoDB AUTO_INCREMENT=39 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `quiz_question`
--

INSERT INTO `quiz_question` (`quiz_question_id`, `quiz_id`, `question_text`, `question_type_id`, `points`, `date_added`, `answer`) VALUES
(33, 5, '<p>q</p>\r\n', 2, 0, '2014-01-17 04:15:03', 'False'),
(34, 3, '<p>Php Stands for ?</p>\r\n', 1, 0, '2014-01-17 12:25:17', 'C'),
(35, 3, '<p>Echo is a Php code that display the output.</p>\r\n', 2, 0, '2014-01-17 12:26:18', 'True'),
(36, 6, '<p>sample</p>\r\n', 1, 0, '2020-12-21 10:05:09', 'A'),
(37, 6, '<p>asdasd</p>\r\n', 2, 0, '2020-12-21 10:05:25', 'True'),
(38, 6, '<p>sdsd</p>\r\n', 2, 0, '2020-12-21 10:05:35', 'False');

-- --------------------------------------------------------

--
-- Table structure for table `school_year`
--

DROP TABLE IF EXISTS `school_year`;
CREATE TABLE IF NOT EXISTS `school_year` (
  `school_year_id` int NOT NULL AUTO_INCREMENT,
  `school_year` varchar(100) NOT NULL,
  PRIMARY KEY (`school_year_id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `school_year`
--

INSERT INTO `school_year` (`school_year_id`, `school_year`) VALUES
(2, '2012-2013'),
(3, '2013-2014');

-- --------------------------------------------------------

--
-- Table structure for table `student`
--

DROP TABLE IF EXISTS `student`;
CREATE TABLE IF NOT EXISTS `student` (
  `student_id` int NOT NULL AUTO_INCREMENT,
  `firstname` varchar(100) NOT NULL,
  `lastname` varchar(100) NOT NULL,
  `class_id` int NOT NULL,
  `username` varchar(100) NOT NULL,
  `password` varchar(100) NOT NULL,
  `location` varchar(100) NOT NULL,
  `status` varchar(100) NOT NULL,
  PRIMARY KEY (`student_id`)
) ENGINE=MyISAM AUTO_INCREMENT=220 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `student`
--

INSERT INTO `student` (`student_id`, `firstname`, `lastname`, `class_id`, `username`, `password`, `location`, `status`) VALUES
(113, 'Clifford', 'Ledesma', 13, '21100324', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(112, 'Raymond', 'Serion', 13, '2700372', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(111, 'Mark Dominic', 'Sayon', 13, '21100867', 'heni', 'uploads/mark.jpg', 'Unregistered'),
(108, 'Kaye Angela', 'Cueva', 13, '21101151', '', 'uploads/dp.jpg', 'Unregistered'),
(105, 'Neljie', 'Guirnela', 13, '21101131', '', 'uploads/Koala.jpg', 'Unregistered'),
(106, 'Razel', 'Palermo', 13, '29000676', '', 'uploads/razel.jpg', 'Unregistered'),
(103, 'Jade', 'Gordoncillo', 13, '21100617', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(104, 'Felix Kirby', 'Ubas', 13, '21100277', 'lms10117', 'uploads/kirb.jpg', 'Unregistered'),
(100, 'Jamilah', 'Lonot', 13, '21100303', '', 'uploads/jamila.jpg', 'Unregistered'),
(101, 'Xenia Jane', 'Billones', 13, '21100318', 'sen', 'uploads/xenia.jpg', 'Unregistered'),
(102, 'Carell', 'Catuburan', 13, '21101124', '', 'uploads/carel.jpg', 'Unregistered'),
(97, 'Mary Joy', 'Lambosan', 13, '20101289', '', 'uploads/Desert.jpg', 'Unregistered'),
(98, 'Christine Joy', 'Macaya', 13, '21100579', '', 'uploads/tin.jpg', 'Unregistered'),
(95, 'Ergin Joy', 'Satoc', 13, '21101142', '', 'uploads/ergin.jpg', 'Unregistered'),
(93, 'John Kevin ', 'Lorayna', 7, '111', 'teph', 'uploads/3094_384893504898082_1563225657_n.jpg', 'Registered'),
(94, 'Leah Mae', 'Padilla', 13, '21100471', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(76, 'Jamaica Mae', 'Alipe', 13, '21100555', '123', 'uploads/maica.jpg', 'Registered'),
(107, 'Jose Harry', 'Polondaya', 13, '29001002', 'florypis', 'uploads/harry.jpg', 'Registered'),
(110, 'Zyryn', 'Corugda', 13, '21100881', '', 'uploads/baby.jpg', 'Unregistered'),
(109, 'Rena', 'Lamberto', 13, '29001081', '', 'uploads/ca.jpg', 'Unregistered'),
(99, 'Ryan Teofilo', 'Malbata-an', 13, '21100315', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(96, 'Glecy Marie', 'Navarosa', 13, '20101436', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(209, 'dhalia', 'hofilena', 20, '21300311', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(75, 'Miralyn', 'Pabalate', 13, '21100855', 'em', 'uploads/em2.jpg', 'Unregistered'),
(74, 'Ma. Nonie', 'Mendoza', 13, '21100913', '', 'uploads/nonie.jpg', 'Unregistered'),
(73, 'Stephanie', 'Villanueva', 13, '21101042', 'tephai', 'uploads/3094_384893504898082_1563225657_n.jpg', 'Registered'),
(72, 'Jayvon', 'Pig-ao', 13, '21100547', 'test', 'uploads/von.jpg', 'Unregistered'),
(71, 'Noli', 'Mendoza', 13, '21100556', 'noledel', 'uploads/noli.jpg', 'Registered'),
(134, 'Victor Anthony', 'Jacobo', 12, '21101050', 'akositon', 'uploads/win_boot_screen_16_9_by_medi_dadu-d4s7dc1.gif', 'Registered'),
(135, 'Albert Kezzel', 'Naynay', 14, '20101361', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(136, 'Jorgielyn', 'Serfino', 7, '20100331', 'jorgie', 'uploads/Koala.jpg', 'Registered'),
(137, 'Wina Mae', 'Espenorio', 8, '20100447', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(138, 'Brian Paul', 'Sablan', 7, '29000557', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(139, 'Rodzil', 'Camato', 7, '20100RC', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(140, 'Dean Martin', 'Tingson', 14, '21100665', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(141, 'Jared Reu', 'Windam', 15, '21100695', 'iloveyoujam', 'uploads/1463666_678111108874417_1795412912_n.jpg', 'Registered'),
(142, 'Lee Ann', 'Vertucio', 12, '21100351', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(143, 'Danica', 'Lamis', 12, '21100396', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(144, 'Neovi', 'Devierte', 12, '21100557', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(145, 'Eril Pio', 'Mercado', 12, '21100291', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(146, 'Johnedel', 'Bauno', 12, '21100411', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(147, 'Jerwin', 'Delos Reyes', 12, '21100369', 'jerwin27 cute', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Registered'),
(148, 'Jendrix', 'Victosa', 12, '21100431', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(149, 'Jebson', 'Tordillos', 12, '21100406', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(150, 'Jethro', 'Pansales', 12, '21101273', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(151, 'Karyl June', 'Bacobo', 12, '21100895', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(152, 'Kristelle Shaine', 'Rubi', 12, '21101063', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(153, 'Richelle', 'Villarmia', 12, '20101392', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(154, 'Mae Ann', 'Panugaling', 12, '21100904', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(155, 'Ma. Roxette', 'Infante', 12, '21100421', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(156, 'Savrena Joy', 'Rael', 12, '2100287', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(157, 'Ace John', 'Casuyon', 12, '21100393', 'DianaraSayon', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Registered'),
(158, 'Rose Mae', 'Pido', 12, '21101195', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(159, 'Mary Ann', 'Panaguiton', 12, '21100701', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(162, 'kimberly kaye', 'salvatierra', 14, '21101182', 'kimzteng', 'uploads/29001002.jpg', 'Registered'),
(210, 'cherylda', 'ohiman', 20, '21300036', 'sawsa', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Registered'),
(164, 'Alit', 'Arvin', 14, '20101605', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(165, 'Ana Mae', 'Alquizar', 14, '21100785', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(166, 'Thessalonica', 'Arroz', 14, '21100651', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(167, 'Leslie', 'Campo', 14, '21100265', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(168, 'Ace', 'Casolino', 14, '27000921', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(169, 'Michael Jed', 'Flores', 14, '21100820', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(172, 'Hennie Rose', 'Laz', 14, '21100805', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(171, 'Joy', 'Macahilig', 14, '21100464', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(173, 'Ma. Nieva', 'Manuel ', 14, '21100711', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(174, 'Devina', 'Navarro', 14, '21100711', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(175, 'Aimee', 'Orlido', 14, '21100654', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(176, 'Mary Grace', 'Quizan', 14, '21100772', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(177, 'John Christopher', 'Reguindin', 14, '21100418', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(178, 'Mary Ann', 'Somosa', 14, '21101150', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(179, 'Marrianne', 'Tumala', 14, '21100710', 'test', 'uploads/win_boot_screen_16_9_by_medi_dadu-d4s7dc1.gif', 'Registered'),
(180, 'Deo Christopher', 'Tribaco', 14, '21101227', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(181, 'Jerson', 'Vargas', 14, '21100819', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(182, 'Valencia', 'Jeralice', 14, '29000405', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(183, 'Cristine', 'Yanson', 14, '21101148', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(184, 'Ariane', 'Alix', 17, '21201166', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(185, 'Mark Arvin', 'Arandilla', 17, '21201453', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(186, 'Ryan Carl', 'Biaquis', 17, '21201244', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(187, 'Ria', 'Bitar', 17, '21201282', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(188, 'Jeremae', 'Bustamante', 17, '21200798', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(189, 'Rhen Mark', 'Callado', 17, '21201012', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(190, 'Ma. Geraldine', 'Carisma', 17, '21201219', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(191, 'Jenny', 'Casapao', 17, '21200855', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(192, 'Welson', 'Castro', 17, '120733', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(193, 'Kimberly Hope', 'Centina', 17, '21201338', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(194, 'Sandra', 'Gomez', 17, '21201335', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(195, 'Dona Jean', 'Guardialao', 17, '21201113', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(196, 'Jeara Mae', 'Guttierrez', 17, '21200782', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(197, 'Mary Joy', 'Jimenez', 17, '21201437', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(198, 'Cyril', 'Lambayong', 17, '21201163', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(199, 'Angelie', 'Lape', 17, '21201356', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(200, 'Jamine', 'Navarosa', 17, '21201115', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(201, 'Allen Joshua', 'Nicor', 17, '21201430', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(202, 'Charis', 'Onate', 17, '21200984', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(203, 'Ikea', 'Padonio', 17, '20100527', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(204, 'Marissa', 'Pasco', 17, '21200935', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(205, 'Kenneth', 'Sayon', 17, '21201268', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(206, 'Mary Grace', 'Morales', 14, '21100293', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(207, 'Danica', 'Delarmente', 14, '21100613', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(208, 'Irish Dawn', 'Belo', 19, '21300413', 'olebirish', 'uploads/Desert.jpg', 'Registered'),
(211, 'val', 'roushen', 7, '201011231', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(212, 'chrystelle Marie', 'Belecina', 15, '21200363', 'chrys', 'uploads/380903_288008981235527_682004916_n.jpg', 'Registered'),
(213, 'kearl joy', 'bartolome', 18, '21300410', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(214, 'marie', 'rojo', 18, '21300375', 'maayeeh', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Registered'),
(215, 'cristine', 'trespuer', 18, '21300258', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(216, 'arian', 'baldostamon', 18, '21300176', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(217, 'Alyssa', 'David', 17, '21200507', '', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Unregistered'),
(218, 'josie', 'banday', 7, '20100452', 'heaven', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Registered'),
(219, 'Claire ', 'Blake', 18, '2011120', 'cblake123', 'uploads/NO-IMAGE-AVAILABLE.jpg', 'Registered');

-- --------------------------------------------------------

--
-- Table structure for table `student_assignment`
--

DROP TABLE IF EXISTS `student_assignment`;
CREATE TABLE IF NOT EXISTS `student_assignment` (
  `student_assignment_id` int NOT NULL AUTO_INCREMENT,
  `assignment_id` int NOT NULL,
  `floc` varchar(100) NOT NULL,
  `assignment_fdatein` varchar(50) NOT NULL,
  `fdesc` varchar(100) NOT NULL,
  `fname` varchar(50) NOT NULL,
  `student_id` int NOT NULL,
  `grade` varchar(5) NOT NULL,
  PRIMARY KEY (`student_assignment_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `student_assignment`
--

INSERT INTO `student_assignment` (`student_assignment_id`, `assignment_id`, `floc`, `assignment_fdatein`, `fdesc`, `fname`, `student_id`, `grade`) VALUES
(1, 31, 'admin/uploads/7820_File_sample.pdf', '2020-12-21 10:12:04', 'aaa', 'asdasd', 219, '');

-- --------------------------------------------------------

--
-- Table structure for table `student_backpack`
--

DROP TABLE IF EXISTS `student_backpack`;
CREATE TABLE IF NOT EXISTS `student_backpack` (
  `file_id` int NOT NULL AUTO_INCREMENT,
  `floc` varchar(100) NOT NULL,
  `fdatein` varchar(100) NOT NULL,
  `fdesc` varchar(100) NOT NULL,
  `student_id` int NOT NULL,
  `fname` varchar(100) NOT NULL,
  PRIMARY KEY (`file_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `student_backpack`
--

INSERT INTO `student_backpack` (`file_id`, `floc`, `fdatein`, `fdesc`, `student_id`, `fname`) VALUES
(1, 'admin/uploads/2658_File_kevin.docx', '2014-02-13 11:11:50', 'test', 210, 'test'),
(2, 'admin/uploads/9782_File_sample.pdf', '2020-12-21 10:12:54', 'adasd', 219, '234234'),
(3, 'admin/uploads/6898_File_sample.pdf', '2020-12-21 10:12:54', 'adasd', 219, '234234'),
(4, 'admin/uploads/3579_File_sample.pdf', '2020-12-21 10:12:54', 'adasd', 219, '234234');

-- --------------------------------------------------------

--
-- Table structure for table `student_class_quiz`
--

DROP TABLE IF EXISTS `student_class_quiz`;
CREATE TABLE IF NOT EXISTS `student_class_quiz` (
  `student_class_quiz_id` int NOT NULL AUTO_INCREMENT,
  `class_quiz_id` int NOT NULL,
  `student_id` int NOT NULL,
  `student_quiz_time` varchar(100) NOT NULL,
  `grade` varchar(100) NOT NULL,
  PRIMARY KEY (`student_class_quiz_id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `student_class_quiz`
--

INSERT INTO `student_class_quiz` (`student_class_quiz_id`, `class_quiz_id`, `student_id`, `student_quiz_time`, `grade`) VALUES
(1, 15, 107, '3600', '0 out of 2'),
(2, 16, 136, '3600', '0 out of 0'),
(3, 17, 219, '3600', '1 out of 3');

-- --------------------------------------------------------

--
-- Table structure for table `subject`
--

DROP TABLE IF EXISTS `subject`;
CREATE TABLE IF NOT EXISTS `subject` (
  `subject_id` int NOT NULL AUTO_INCREMENT,
  `subject_code` varchar(100) NOT NULL,
  `subject_title` varchar(100) NOT NULL,
  `category` varchar(100) NOT NULL,
  `description` longtext NOT NULL,
  `unit` int NOT NULL,
  `Pre_req` varchar(100) NOT NULL,
  `semester` varchar(100) NOT NULL,
  PRIMARY KEY (`subject_id`)
) ENGINE=MyISAM AUTO_INCREMENT=43 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `subject`
--

INSERT INTO `subject` (`subject_id`, `subject_code`, `subject_title`, `category`, `description`, `unit`, `Pre_req`, `semester`) VALUES
(14, 'IS 411A', 'Senior Systems Project 1', '', '<p><span style=\"font-size: medium;\"><em>About the Subject</em></span></p>\r\n<p>This subject comprisea topics about systems development, SDLC methodologies, Conceptual Framework, diagrams such as DFD, ERD and Flowchart and writing a thesis proposal.</p>\r\n<p>&nbsp;</p>\r\n<p>The project requirement for this subject are:</p>\r\n<p>Chapters (1-5) Thesis Proposal</p>\r\n<p>100% Running System at the end of semester</p>\r\n<p>&nbsp;</p>', 3, '', ''),
(15, 'IS 412', 'Effective Human Communication for IT Professional', '', '<p><span style=\"font-size: medium;\"><em>About the Subject</em></span></p>\r\n<p>This subject is intended for IT students to develop or enhance communication skills that will be beneficial especially when used in the business industry. The lesson includes Verbal Communication (Written and Oral), Non-verbal Communication, etc.</p>', 3, '', ''),
(16, 'IS 311', 'Programming Languages', '', '<pre class=\"coursera-course-heading\" data-msg=\"coursera-course-about\"><span style=\"font-size: medium;\"><em>About the Subject</em></span></pre>\r\n<div class=\"coursera-course-detail\" data-user-generated=\"data-user-generated\">Learn many of the concepts that underlie all programming languages. Develop a programming style known as functional programming and contrast it with object-oriented programming. Through experience writing programs and studying three different languages, learn the key issues in designing and using programming languages, such as modularity and the complementary benefits of static and dynamic typing. This course is neither particularly theoretical nor just about programming specifics &ndash; it will give you a framework for understanding how to use language constructs effectively and how to design correct and elegant programs. By using different languages, you learn to think more deeply than in terms of the particular syntax of one language. The emphasis on functional programming is essential for learning how to write robust, reusable, composable, and elegant programs &ndash; in any language.</div>\r\n<h2 class=\"coursera-course-detail\" data-user-generated=\"data-user-generated\">&nbsp;</h2>\r\n<pre class=\"coursera-course-detail\" data-user-generated=\"data-user-generated\"><span style=\"font-size: medium;\"><em>&nbsp;Course Syllabus</em></span></pre>\r\n<div class=\"coursera-course-detail\" data-user-generated=\"data-user-generated\">\r\n<ul>\r\n<li>Syntax vs. semantics vs. idioms vs. libraries vs. tools</li>\r\n<li>ML basics (bindings, conditionals, records, functions)</li>\r\n<li>Recursive functions and recursive types</li>\r\n<li>Benefits of no mutation</li>\r\n<li>Algebraic datatypes, pattern matching</li>\r\n<li>Tail recursion</li>\r\n<li>First-class functions and function closures</li>\r\n<li>Lexical scope</li>\r\n<li>Equivalence and effects</li>\r\n<li>Parametric polymorphism and container types</li>\r\n<li>Type inference</li>\r\n<li>Abstract types and modules</li>\r\n<li>Racket basics</li>\r\n<li>Dynamic vs. static typing</li>\r\n<li>Implementing languages, especially higher-order functions</li>\r\n<li>Macro</li>\r\n<li>Ruby basics</li>\r\n<li>Object-oriented programming</li>\r\n<li>Pure object-orientation</li>\r\n<li>Implementing dynamic dispatch</li>\r\n<li>Multiple inheritance, interfaces, and mixins</li>\r\n<li>OOP vs. functional decomposition and extensibility</li>\r\n<li>Subtyping for records, functions, and objects</li>\r\n<li>Subtyping</li>\r\n<li>Class-based subtyping</li>\r\n<li>Subtyping vs. parametric polymorphism; bounded polymorphism</li>\r\n</ul>\r\n</div>', 3, '', ''),
(17, 'IS 413', 'Introduction to the IM Professional and Ethics', '', '<p>This subject discusses about Ethics, E-Commerce, Cybercrime Law, Computer Security, etc.</p>', 0, '', ''),
(22, 'IS 221', 'Application Development', '', '', 3, '', '2nd'),
(23, 'IS 222', 'Network and Internet Technology', '', '', 3, '', '2nd'),
(24, 'IS 223', 'Business Process', '', '', 3, '', '2nd'),
(25, 'IS 224', 'Discrete Structures', '', '', 3, '', '2nd'),
(26, 'IS 227', 'IS Programming 2', '', '', 3, '', '2nd'),
(27, 'SS POL GOV', 'Politics and Governance with Philippine Constitution', '', '', 3, '', '2nd'),
(28, 'LIT 1', 'Philippine  Literature', '', '', 3, '', '2nd'),
(29, 'ACCTG 2', 'Fundamentals of Accounting 2', '', '', 3, '', '2nd'),
(30, 'PE 4', 'Team Sports', '', '', 3, '', '2nd'),
(31, 'IS 302', 'Survey of Programming Languages', '', '', 3, '', '2nd'),
(32, 'IS 303', 'Structured Query Language', '', '', 3, '', '2nd'),
(33, 'IS 321', 'Information System Planning', '', '', 3, '', '2nd'),
(34, 'IS 322', 'Management of Technology', '', '', 3, '', '2nd'),
(35, 'IS 323', 'E-commerce Strategy Architectural', '', '', 3, '', '2nd'),
(36, 'IS 324', 'System Analysis and Design', '', '', 3, '', '2nd'),
(37, 'Law 1', 'Law on Obligation and Contracts', '', '', 3, '', '2nd'),
(38, 'Philo 1', 'Social Philosophy & Logic', '', '', 3, '', '2nd'),
(39, 'MQTB', 'Quantitative Techniques in Business', '', '', 3, '', '2nd'),
(40, 'RIZAL', 'Rizal: Life and Works', '', '<p>COURSE OUTLINE<br />\r\n1. Course Code : RIZAL</p>\r\n\r\n<p>2. Course Title &nbsp;: RIZAL (Rizal Life and Works)<br />\r\n3. Pre-requisite : none<br />\r\n5. Credit/ Class Schedule : 3 units; 3 hrs/week<br />\r\n6. Course Description&nbsp;<br />\r\n1. A critical analysis of Jose Rizal&rsquo;s life and ideas as reflected in his biography, his novels Noli Me Tangere and El Filibusterismo and in his other writings composed of essays and poems to provide the students a value based reference for reacting to certain ideas and behavior.<br />\r\n<br />\r\n<strong>PROGRAM OBJECTIVES</strong><br />\r\n1. To instill in the students human values and cultural refinement through the humanities and social sciences.<br />\r\n2. To inculcate high ethical standards in the students through its integration in the learning activities.<br />\r\n3. To have critical studies and discussions why Rizal is made the national hero of the Philippines.<br />\r\n<br />\r\nTOPICS:&nbsp;<br />\r\n1. A Hero is Born&nbsp;<br />\r\n2. Childhood Days in Calamba<br />\r\n3. School Days in Binan<br />\r\n4. Triumphs in the Ateneo<br />\r\n5. At the UST<br />\r\n6. In Spain<br />\r\n7. Paris to Berlin<br />\r\n8. Noli Me Tangere<br />\r\n9. Elias and Salome<br />\r\n10. Rizal&rsquo;s Tour of Europe with with Viola<br />\r\n11. Back to Calamba<br />\r\n12. HK, Macao and Japan<br />\r\n13. Rizal in Japan<br />\r\n14. Rizal in America<br />\r\n15. Life and Works in London<br />\r\n16. In Gay Paris<br />\r\n17. Rizal in Brussles<br />\r\n18. In Madrid<br />\r\n19. El Filibusterismo<br />\r\n20. In Hong Kong<br />\r\n21. Exile in Dapitan<br />\r\n22. The Trial of Rizal<br />\r\n23. Martyrdom at Bagumbayan<br />\r\n<br />\r\nTextbook and References:<br />\r\n1. Rizal&rsquo;s Life, Works and Writings (The Centennial Edition) by: Gregorio F. Zaide<br />\r\nand Sonia M. Zaide Quezon City, 1988. All Nations Publishing Co.<br />\r\n2. Coates, Austin. Rizal: First Filipino Nationalist and Martyr, Quezon City, UP Press 1999.<br />\r\n3. Constantino, Renato. Veneration Without Understanding. Quezon City, UP Press Inc., 2001.<br />\r\n4. Dela Cruz, W. &amp; Zulueta, M. Rizal: Buhay at Kaisipan. Manila, NBS Publications 2002.<br />\r\n5. Ocampo, Ambeth. Rizal Without the Overcoat (New Edition). Pasig City, anvil Publishing House 2002.<br />\r\n6. Odullo-de Guzman, Maria. Noli Me Tangere and El Filibusterismo. Manila, NBS Publications 1998.<br />\r\n7. Palma, Rafael. Rizal: The Pride of the Malay Race. Manila, Saint Anthony Company 2000.<br />\r\n8.Romero, M.C. &amp; Sta Roman, J. Rizal &amp; the Development of Filipino Consciousness (Third Edition). Manila, JMC Press Inc., 2001.<br />\r\n<br />\r\nCourse Evaluation:<br />\r\n<br />\r\n1. Quizzes : 30 %<br />\r\n2. Exams : 40 %<br />\r\n3. Class Standing : 20 %<br />\r\n- recitation<br />\r\n- attendance<br />\r\n- behavior<br />\r\n4. Final Grade<br />\r\n- 40 % previous grade<br />\r\n- 60 % current grade</p>\r\n', 3, '', '2nd'),
(41, 'IS 411B', 'Senior Systems Project 2', '', '', 3, '', '2nd'),
(42, '1234', 'Sample Subject', '', '<p>Sample Only</p>\r\n', 3, '', '1st');

-- --------------------------------------------------------

--
-- Table structure for table `teacher`
--

DROP TABLE IF EXISTS `teacher`;
CREATE TABLE IF NOT EXISTS `teacher` (
  `teacher_id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(100) NOT NULL,
  `password` varchar(200) NOT NULL,
  `firstname` varchar(100) NOT NULL,
  `lastname` varchar(100) NOT NULL,
  `department_id` int NOT NULL,
  `location` varchar(200) NOT NULL,
  `about` varchar(500) NOT NULL,
  `teacher_status` varchar(20) NOT NULL,
  `teacher_stat` varchar(100) NOT NULL,
  PRIMARY KEY (`teacher_id`)
) ENGINE=MyISAM AUTO_INCREMENT=20 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `teacher`
--

INSERT INTO `teacher` (`teacher_id`, `username`, `password`, `firstname`, `lastname`, `department_id`, `location`, `about`, `teacher_status`, `teacher_stat`) VALUES
(9, '1001', 'test', 'Jomar', 'Pabuaya', 4, 'uploads/NO-IMAGE-AVAILABLE.jpg', '', 'Registered', 'Deactivated'),
(5, '1002', 'red', 'Cristine', 'Redoblo', 4, 'uploads/NO-IMAGE-AVAILABLE.jpg', '', '', 'Activated'),
(11, '1003', 'aladin', 'Aladin', 'Cabrera', 4, 'uploads/NO-IMAGE-AVAILABLE.jpg', '', '', 'Activated'),
(13, 'test', 'test', 'Rammel', 'Cadagat', 4, 'uploads/NO-IMAGE-AVAILABLE.jpg', '', '', 'Activated'),
(12, '1000', 'morante', 'Ruby Mae ', 'Morante', 4, 'uploads/NO-IMAGE-AVAILABLE.jpg', '<p style=\"text-align: justify;\">Dan Grossman has taught programming languages at the University of Washington since 2003. During his 10 years as a faculty member, his department&rsquo;s undergraduate students have elected him &ldquo;teacher of the year&rdquo; twice and awarded him second place once. His research, resulting in over 50 peer-reviewed publications, has covered the theory, design, and implementation of programming languages, as well as connections to computer architecture and softwar', '', 'Activated'),
(14, 'honey', 'lee', 'Honeylee', 'Magbanua', 10, 'uploads/NO-IMAGE-AVAILABLE.jpg', '', '', 'Deactivated'),
(15, 'chaw', 'chaw', 'Charito ', 'Puray', 4, 'uploads/NO-IMAGE-AVAILABLE.jpg', '', '', 'Activated'),
(17, '', '', 'Lovelyn ', 'Layson', 5, 'uploads/NO-IMAGE-AVAILABLE.jpg', '', '', 'Activated'),
(18, 'test123', 'test123', 'Allan', 'Dela Torre', 4, 'uploads/NO-IMAGE-AVAILABLE.jpg', '', 'Registered', 'Activated'),
(19, 'delam', 'denise', 'Denesa', 'Lamique', 4, 'uploads/NO-IMAGE-AVAILABLE.jpg', '', 'Registered', 'Activated');

-- --------------------------------------------------------

--
-- Table structure for table `teacher_backpack`
--

DROP TABLE IF EXISTS `teacher_backpack`;
CREATE TABLE IF NOT EXISTS `teacher_backpack` (
  `file_id` int NOT NULL AUTO_INCREMENT,
  `floc` varchar(100) NOT NULL,
  `fdatein` varchar(100) NOT NULL,
  `fdesc` varchar(100) NOT NULL,
  `teacher_id` int NOT NULL,
  `fname` varchar(100) NOT NULL,
  PRIMARY KEY (`file_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `teacher_class`
--

DROP TABLE IF EXISTS `teacher_class`;
CREATE TABLE IF NOT EXISTS `teacher_class` (
  `teacher_class_id` int NOT NULL AUTO_INCREMENT,
  `teacher_id` int NOT NULL,
  `class_id` int NOT NULL,
  `subject_id` int NOT NULL,
  `thumbnails` varchar(100) NOT NULL,
  `school_year` varchar(100) NOT NULL,
  PRIMARY KEY (`teacher_class_id`)
) ENGINE=InnoDB AUTO_INCREMENT=187 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `teacher_class`
--

INSERT INTO `teacher_class` (`teacher_class_id`, `teacher_id`, `class_id`, `subject_id`, `thumbnails`, `school_year`) VALUES
(97, 9, 7, 15, 'admin/uploads/thumbnails.jpg', '2012-2013'),
(135, 0, 22, 29, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(151, 5, 7, 14, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(152, 5, 8, 14, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(153, 5, 13, 36, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(157, 18, 15, 23, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(158, 18, 16, 23, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(159, 18, 12, 23, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(160, 18, 7, 29, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(165, 134, 15, 23, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(167, 12, 13, 35, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(168, 12, 14, 35, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(170, 12, 16, 24, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(172, 18, 13, 39, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(173, 18, 14, 39, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(174, 13, 12, 16, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(175, 13, 13, 16, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(176, 13, 14, 16, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(177, 14, 12, 32, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(178, 14, 13, 32, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(179, 14, 14, 32, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(180, 19, 13, 22, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(181, 12, 20, 24, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(183, 12, 18, 24, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(184, 12, 17, 25, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(185, 12, 7, 22, 'admin/uploads/thumbnails.jpg', '2013-2014'),
(186, 9, 18, 42, 'admin/uploads/thumbnails.jpg', '2013-2014');

-- --------------------------------------------------------

--
-- Table structure for table `teacher_class_announcements`
--

DROP TABLE IF EXISTS `teacher_class_announcements`;
CREATE TABLE IF NOT EXISTS `teacher_class_announcements` (
  `teacher_class_announcements_id` int NOT NULL AUTO_INCREMENT,
  `content` varchar(500) NOT NULL,
  `teacher_id` varchar(100) NOT NULL,
  `teacher_class_id` int NOT NULL,
  `date` varchar(50) NOT NULL,
  PRIMARY KEY (`teacher_class_announcements_id`)
) ENGINE=InnoDB AUTO_INCREMENT=40 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `teacher_class_announcements`
--

INSERT INTO `teacher_class_announcements` (`teacher_class_announcements_id`, `content`, `teacher_id`, `teacher_class_id`, `date`) VALUES
(2, '<p><strong>Project Deadline</strong></p>\r\n\r\n<p>In December 1st week&nbsp; system must fully functioning.</p>\r\n\r\n<p><br />\r\n&nbsp;</p>\r\n', '9', 87, '2013-10-30 13:21:13'),
(21, '<p>fsaf</p>\r\n', '9', 87, '2013-10-30 14:33:21'),
(31, '<p>Hi im kevin i edit this</p>\r\n', '9', 87, '2013-10-30 15:41:56'),
(33, '<p>hello teph</p>\r\n', '9', 95, '2013-10-30 17:44:28'),
(34, '<p>hello guys</p>\r\n', '9', 95, '2013-11-02 10:51:39'),
(35, '<p>dsdasd</p>\r\n', '12', 147, '2013-11-16 13:59:33'),
(36, '<p>BSIS 1A: Submit assignment on November 20, 2013 before 5pm.</p>\r\n', '12', 154, '2013-11-18 15:29:34'),
(37, '<p>aaaaa<br />\r\n&nbsp;</p>\r\n', '12', 167, '2014-01-17 14:36:32'),
(38, '<p>wala klase<img alt=\"sad\" src=\"http://localhost/lms/admin/vendors/ckeditor/plugins/smiley/images/sad_smile.gif\" style=\"height:20px; width:20px\" title=\"sad\" /></p>\r\n', '12', 167, '2014-02-13 13:45:59'),
(39, '<p>Test</p>\r\n', '9', 186, '2020-12-21 09:59:00');

-- --------------------------------------------------------

--
-- Table structure for table `teacher_class_student`
--

DROP TABLE IF EXISTS `teacher_class_student`;
CREATE TABLE IF NOT EXISTS `teacher_class_student` (
  `teacher_class_student_id` int NOT NULL AUTO_INCREMENT,
  `teacher_class_id` int NOT NULL,
  `student_id` int NOT NULL,
  `teacher_id` int NOT NULL,
  PRIMARY KEY (`teacher_class_student_id`)
) ENGINE=InnoDB AUTO_INCREMENT=383 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `teacher_class_student`
--

INSERT INTO `teacher_class_student` (`teacher_class_student_id`, `teacher_class_id`, `student_id`, `teacher_id`) VALUES
(31, 165, 141, 134),
(32, 165, 134, 134),
(54, 167, 113, 12),
(55, 167, 112, 12),
(57, 167, 108, 12),
(58, 167, 105, 12),
(59, 167, 106, 12),
(60, 167, 103, 12),
(61, 167, 104, 12),
(62, 167, 100, 12),
(63, 167, 101, 12),
(64, 167, 102, 12),
(65, 167, 97, 12),
(66, 167, 98, 12),
(67, 167, 95, 12),
(68, 167, 94, 12),
(69, 167, 76, 12),
(70, 167, 107, 12),
(71, 167, 110, 12),
(72, 167, 109, 12),
(73, 167, 99, 12),
(74, 167, 96, 12),
(75, 167, 75, 12),
(76, 167, 74, 12),
(77, 167, 73, 12),
(78, 167, 72, 12),
(79, 167, 71, 12),
(80, 168, 135, 12),
(81, 168, 140, 12),
(82, 168, 162, 12),
(83, 168, 164, 12),
(84, 168, 165, 12),
(85, 168, 166, 12),
(86, 168, 167, 12),
(87, 168, 168, 12),
(88, 168, 169, 12),
(89, 168, 172, 12),
(90, 168, 171, 12),
(91, 168, 173, 12),
(92, 168, 174, 12),
(93, 168, 175, 12),
(94, 168, 176, 12),
(95, 168, 177, 12),
(96, 168, 178, 12),
(97, 168, 179, 12),
(98, 168, 180, 12),
(99, 168, 181, 12),
(100, 168, 182, 12),
(101, 168, 183, 12),
(102, 168, 206, 12),
(103, 168, 207, 12),
(127, 172, 113, 18),
(128, 172, 112, 18),
(129, 172, 111, 18),
(130, 172, 108, 18),
(131, 172, 105, 18),
(132, 172, 106, 18),
(133, 172, 103, 18),
(134, 172, 104, 18),
(135, 172, 100, 18),
(136, 172, 101, 18),
(137, 172, 102, 18),
(138, 172, 97, 18),
(139, 172, 98, 18),
(140, 172, 95, 18),
(141, 172, 94, 18),
(142, 172, 76, 18),
(143, 172, 107, 18),
(144, 172, 110, 18),
(145, 172, 109, 18),
(146, 172, 99, 18),
(147, 172, 96, 18),
(148, 172, 75, 18),
(149, 172, 74, 18),
(150, 172, 73, 18),
(151, 172, 72, 18),
(152, 172, 71, 18),
(153, 173, 135, 18),
(154, 173, 140, 18),
(155, 173, 162, 18),
(156, 173, 164, 18),
(157, 173, 165, 18),
(158, 173, 166, 18),
(159, 173, 167, 18),
(160, 173, 168, 18),
(161, 173, 169, 18),
(162, 173, 172, 18),
(163, 173, 171, 18),
(164, 173, 173, 18),
(165, 173, 174, 18),
(166, 173, 175, 18),
(167, 173, 176, 18),
(168, 173, 177, 18),
(169, 173, 178, 18),
(170, 173, 179, 18),
(171, 173, 180, 18),
(172, 173, 181, 18),
(173, 173, 182, 18),
(174, 173, 183, 18),
(175, 173, 206, 18),
(176, 173, 207, 18),
(177, 174, 134, 13),
(178, 174, 142, 13),
(179, 174, 143, 13),
(180, 174, 144, 13),
(181, 174, 145, 13),
(182, 174, 146, 13),
(183, 174, 147, 13),
(184, 174, 148, 13),
(185, 174, 149, 13),
(186, 174, 150, 13),
(187, 174, 151, 13),
(188, 174, 152, 13),
(189, 174, 153, 13),
(190, 174, 154, 13),
(191, 174, 155, 13),
(192, 174, 156, 13),
(193, 174, 157, 13),
(194, 174, 158, 13),
(195, 174, 159, 13),
(196, 175, 113, 13),
(197, 175, 112, 13),
(198, 175, 111, 13),
(199, 175, 108, 13),
(200, 175, 105, 13),
(201, 175, 106, 13),
(202, 175, 103, 13),
(203, 175, 104, 13),
(204, 175, 100, 13),
(205, 175, 101, 13),
(206, 175, 102, 13),
(207, 175, 97, 13),
(208, 175, 98, 13),
(209, 175, 95, 13),
(210, 175, 94, 13),
(211, 175, 76, 13),
(212, 175, 107, 13),
(213, 175, 110, 13),
(214, 175, 109, 13),
(215, 175, 99, 13),
(216, 175, 96, 13),
(217, 175, 75, 13),
(218, 175, 74, 13),
(219, 175, 73, 13),
(220, 175, 72, 13),
(221, 175, 71, 13),
(222, 176, 135, 13),
(223, 176, 140, 13),
(224, 176, 162, 13),
(225, 176, 164, 13),
(226, 176, 165, 13),
(227, 176, 166, 13),
(228, 176, 167, 13),
(229, 176, 168, 13),
(230, 176, 169, 13),
(231, 176, 172, 13),
(232, 176, 171, 13),
(233, 176, 173, 13),
(234, 176, 174, 13),
(235, 176, 175, 13),
(236, 176, 176, 13),
(237, 176, 177, 13),
(238, 176, 178, 13),
(239, 176, 179, 13),
(240, 176, 180, 13),
(241, 176, 181, 13),
(242, 176, 182, 13),
(243, 176, 183, 13),
(244, 176, 206, 13),
(245, 176, 207, 13),
(246, 177, 134, 14),
(247, 177, 142, 14),
(248, 177, 143, 14),
(249, 177, 144, 14),
(250, 177, 145, 14),
(251, 177, 146, 14),
(252, 177, 147, 14),
(253, 177, 148, 14),
(254, 177, 149, 14),
(255, 177, 150, 14),
(256, 177, 151, 14),
(257, 177, 152, 14),
(258, 177, 153, 14),
(259, 177, 154, 14),
(260, 177, 155, 14),
(261, 177, 156, 14),
(262, 177, 157, 14),
(263, 177, 158, 14),
(264, 177, 159, 14),
(265, 178, 113, 14),
(266, 178, 112, 14),
(267, 178, 111, 14),
(268, 178, 108, 14),
(269, 178, 105, 14),
(270, 178, 106, 14),
(271, 178, 103, 14),
(272, 178, 104, 14),
(273, 178, 100, 14),
(274, 178, 101, 14),
(275, 178, 102, 14),
(276, 178, 97, 14),
(277, 178, 98, 14),
(278, 178, 95, 14),
(279, 178, 94, 14),
(280, 178, 76, 14),
(281, 178, 107, 14),
(282, 178, 110, 14),
(283, 178, 109, 14),
(284, 178, 99, 14),
(285, 178, 96, 14),
(286, 178, 75, 14),
(287, 178, 74, 14),
(288, 178, 73, 14),
(289, 178, 72, 14),
(290, 178, 71, 14),
(291, 179, 135, 14),
(292, 179, 140, 14),
(293, 179, 162, 14),
(294, 179, 164, 14),
(295, 179, 165, 14),
(296, 179, 166, 14),
(297, 179, 167, 14),
(298, 179, 168, 14),
(299, 179, 169, 14),
(300, 179, 172, 14),
(301, 179, 171, 14),
(302, 179, 173, 14),
(303, 179, 174, 14),
(304, 179, 175, 14),
(305, 179, 176, 14),
(306, 179, 177, 14),
(307, 179, 178, 14),
(308, 179, 179, 14),
(309, 179, 180, 14),
(310, 179, 181, 14),
(311, 179, 182, 14),
(312, 179, 183, 14),
(313, 179, 206, 14),
(314, 179, 207, 14),
(315, 180, 113, 19),
(316, 180, 112, 19),
(317, 180, 111, 19),
(318, 180, 108, 19),
(319, 180, 105, 19),
(320, 180, 106, 19),
(321, 180, 103, 19),
(322, 180, 104, 19),
(323, 180, 100, 19),
(324, 180, 101, 19),
(325, 180, 102, 19),
(326, 180, 97, 19),
(327, 180, 98, 19),
(328, 180, 95, 19),
(329, 180, 94, 19),
(330, 180, 76, 19),
(331, 180, 107, 19),
(332, 180, 110, 19),
(333, 180, 109, 19),
(334, 180, 99, 19),
(335, 180, 96, 19),
(336, 180, 75, 19),
(337, 180, 74, 19),
(338, 180, 73, 19),
(339, 180, 72, 19),
(340, 180, 71, 19),
(341, 181, 209, 12),
(342, 181, 210, 12),
(345, 183, 213, 12),
(346, 183, 214, 12),
(347, 183, 215, 12),
(348, 183, 216, 12),
(349, 184, 184, 12),
(350, 184, 185, 12),
(351, 184, 186, 12),
(352, 184, 187, 12),
(353, 184, 188, 12),
(354, 184, 189, 12),
(355, 184, 190, 12),
(356, 184, 191, 12),
(358, 184, 193, 12),
(359, 184, 194, 12),
(360, 184, 195, 12),
(361, 184, 196, 12),
(362, 184, 197, 12),
(363, 184, 198, 12),
(364, 184, 199, 12),
(365, 184, 200, 12),
(366, 184, 201, 12),
(367, 184, 202, 12),
(368, 184, 203, 12),
(369, 184, 204, 12),
(370, 184, 205, 12),
(371, 184, 217, 12),
(372, 184, 192, 12),
(373, 185, 93, 12),
(374, 185, 136, 12),
(375, 185, 138, 12),
(376, 185, 139, 12),
(377, 185, 211, 12),
(378, 186, 213, 9),
(379, 186, 214, 9),
(380, 186, 215, 9),
(381, 186, 216, 9),
(382, 186, 219, 9);

-- --------------------------------------------------------

--
-- Table structure for table `teacher_notification`
--

DROP TABLE IF EXISTS `teacher_notification`;
CREATE TABLE IF NOT EXISTS `teacher_notification` (
  `teacher_notification_id` int NOT NULL AUTO_INCREMENT,
  `teacher_class_id` int NOT NULL,
  `notification` varchar(100) NOT NULL,
  `date_of_notification` varchar(100) NOT NULL,
  `link` varchar(100) NOT NULL,
  `student_id` int NOT NULL,
  `assignment_id` int NOT NULL,
  PRIMARY KEY (`teacher_notification_id`)
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `teacher_notification`
--

INSERT INTO `teacher_notification` (`teacher_notification_id`, `teacher_class_id`, `notification`, `date_of_notification`, `link`, `student_id`, `assignment_id`) VALUES
(15, 160, 'Submit Assignment file name <b>my_assginment</b>', '2013-11-25 10:39:52', 'view_submit_assignment.php', 93, 16),
(17, 161, 'Submit Assignment file name <b>q</b>', '2013-11-25 15:54:19', 'view_submit_assignment.php', 71, 17),
(18, 186, 'Submit Assignment file name <b>asdasd</b>', '2020-12-21 10:12:04', 'view_submit_assignment.php', 219, 31);

-- --------------------------------------------------------

--
-- Table structure for table `teacher_shared`
--

DROP TABLE IF EXISTS `teacher_shared`;
CREATE TABLE IF NOT EXISTS `teacher_shared` (
  `teacher_shared_id` int NOT NULL AUTO_INCREMENT,
  `teacher_id` int NOT NULL,
  `shared_teacher_id` int NOT NULL,
  `floc` varchar(100) NOT NULL,
  `fdatein` varchar(100) NOT NULL,
  `fdesc` varchar(100) NOT NULL,
  `fname` varchar(100) NOT NULL,
  PRIMARY KEY (`teacher_shared_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `teacher_shared`
--

INSERT INTO `teacher_shared` (`teacher_shared_id`, `teacher_id`, `shared_teacher_id`, `floc`, `fdatein`, `fdesc`, `fname`) VALUES
(1, 12, 14, 'admin/uploads/7939_File_449E26DB.jpg', '2014-02-20 09:55:32', 'sas', 'sss');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
CREATE TABLE IF NOT EXISTS `users` (
  `user_id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(100) NOT NULL,
  `password` varchar(100) NOT NULL,
  `firstname` varchar(100) NOT NULL,
  `lastname` varchar(100) NOT NULL,
  PRIMARY KEY (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=16 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`user_id`, `username`, `password`, `firstname`, `lastname`) VALUES
(13, 'teph', 'teph', 'Stephanie', 'villanueva'),
(14, 'jkev', 'jkev', 'john kevin', 'lorayna'),
(15, 'admin', 'admin', 'admin', 'admin');

-- --------------------------------------------------------

--
-- Table structure for table `user_log`
--

DROP TABLE IF EXISTS `user_log`;
CREATE TABLE IF NOT EXISTS `user_log` (
  `user_log_id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(25) NOT NULL,
  `login_date` varchar(30) NOT NULL,
  `logout_date` varchar(30) NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`user_log_id`)
) ENGINE=InnoDB AUTO_INCREMENT=87 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `user_log`
--

INSERT INTO `user_log` (`user_log_id`, `username`, `login_date`, `logout_date`, `user_id`) VALUES
(1, 'admin', '2013-11-01 11:57:33', '2013-11-18 10:33:54', 10),
(2, 'admin', '2013-11-05 09:52:09', '2013-11-18 10:33:54', 10),
(3, 'admin', '2013-11-08 10:41:09', '2013-11-18 10:33:54', 10),
(4, 'admin', '2013-11-12 22:53:05', '2013-11-18 10:33:54', 10),
(5, 'admin', '2013-11-13 07:07:04', '2013-11-18 10:33:54', 10),
(6, 'admin', '2013-11-13 13:07:58', '2013-11-18 10:33:54', 10),
(7, 'admin', '2013-11-13 13:30:45', '2013-11-18 10:33:54', 10),
(8, 'admin', '2013-11-13 15:25:20', '2013-11-18 10:33:54', 10),
(9, 'admin', '2013-11-13 15:46:28', '2013-11-18 10:33:54', 10),
(10, 'admin', '2013-11-13 16:04:10', '2013-11-18 10:33:54', 10),
(11, 'admin', '2013-11-13 17:31:37', '2013-11-18 10:33:54', 10),
(12, 'admin', '2013-11-13 22:47:45', '2013-11-18 10:33:54', 10),
(13, 'admin', '2013-11-14 10:27:06', '2013-11-18 10:33:54', 10),
(14, 'admin', '2013-11-14 10:27:55', '2013-11-18 10:33:54', 10),
(15, 'admin', '2013-11-14 10:38:08', '2013-11-18 10:33:54', 10),
(16, 'admin', '2013-11-14 10:38:09', '2013-11-18 10:33:54', 10),
(17, 'admin', '2013-11-14 10:41:06', '2013-11-18 10:33:54', 10),
(18, 'admin', '2013-11-14 11:44:08', '2013-11-18 10:33:54', 10),
(19, 'admin', '2013-11-14 21:53:56', '2013-11-18 10:33:54', 10),
(20, 'admin', '2013-11-14 22:03:53', '2013-11-18 10:33:54', 10),
(21, 'admin', '2013-11-16 13:40:56', '2013-11-18 10:33:54', 10),
(22, 'admin', '2013-11-18 10:22:07', '2013-11-18 10:33:54', 10),
(23, 'jkev', '2013-11-18 10:33:59', '2014-02-13 11:19:36', 14),
(24, 'jkev', '2013-11-18 15:20:45', '2014-02-13 11:19:36', 14),
(25, 'jkev', '2013-11-18 15:42:04', '2014-02-13 11:19:36', 14),
(26, 'jkev', '2013-11-18 16:30:14', '2014-02-13 11:19:36', 14),
(27, 'jkev', '2013-11-18 16:36:44', '2014-02-13 11:19:36', 14),
(28, 'jkev', '2013-11-18 17:39:55', '2014-02-13 11:19:36', 14),
(29, 'jkev', '2013-11-18 20:06:49', '2014-02-13 11:19:36', 14),
(30, 'jkev', '2013-11-23 08:04:27', '2014-02-13 11:19:36', 14),
(31, 'teph', '2013-11-23 12:02:27', '2013-11-30 21:33:02', 13),
(32, 'teph', '2013-11-24 08:55:55', '2013-11-30 21:33:02', 13),
(33, 'jkev', '2013-11-25 10:32:16', '2014-02-13 11:19:36', 14),
(34, 'jkev', '2013-11-25 14:33:05', '2014-02-13 11:19:36', 14),
(35, 'jkev', '2013-11-25 15:02:47', '2014-02-13 11:19:36', 14),
(36, 'jkev', '2013-11-25 21:08:19', '2014-02-13 11:19:36', 14),
(37, 'jkev', '2013-11-25 23:49:58', '2014-02-13 11:19:36', 14),
(38, 'jkev', '2013-11-26 00:32:22', '2014-02-13 11:19:36', 14),
(39, 'jkev', '2013-11-26 10:39:52', '2014-02-13 11:19:36', 14),
(40, 'jkev', '2013-11-26 21:48:05', '2014-02-13 11:19:36', 14),
(41, 'jkev', '2013-11-28 23:00:00', '2014-02-13 11:19:36', 14),
(42, 'jkev', '2013-11-28 23:00:06', '2014-02-13 11:19:36', 14),
(43, 'jkev', '2013-11-30 21:28:54', '2014-02-13 11:19:36', 14),
(44, 'teph', '2013-11-30 21:32:54', '2013-11-30 21:33:02', 13),
(45, 'jkev', '2013-12-04 12:45:09', '2014-02-13 11:19:36', 14),
(46, 'teph', '2013-12-04 14:02:19', '', 13),
(47, 'jkev', '2013-12-11 11:56:15', '2014-02-13 11:19:36', 14),
(48, 'jkev', '2013-12-11 12:04:44', '2014-02-13 11:19:36', 14),
(49, 'jkev', '2013-12-12 09:44:34', '2014-02-13 11:19:36', 14),
(50, 'jkev', '2013-12-13 01:48:23', '2014-02-13 11:19:36', 14),
(51, 'jkev', '2013-12-27 09:13:20', '2014-02-13 11:19:36', 14),
(52, 'jkev', '2013-12-27 10:18:38', '2014-02-13 11:19:36', 14),
(53, 'jkev', '2013-12-27 10:35:43', '2014-02-13 11:19:36', 14),
(54, 'jkev', '2013-12-27 11:08:54', '2014-02-13 11:19:36', 14),
(55, 'jkev', '2013-12-27 11:20:25', '2014-02-13 11:19:36', 14),
(56, 'jkev', '2013-12-27 11:41:58', '2014-02-13 11:19:36', 14),
(57, 'jkev', '2013-12-27 11:43:10', '2014-02-13 11:19:36', 14),
(58, 'jkev', '2013-12-27 14:54:57', '2014-02-13 11:19:36', 14),
(59, 'jkev', '2014-01-12 20:08:26', '2014-02-13 11:19:36', 14),
(60, 'jkev', '2014-01-13 15:24:07', '2014-02-13 11:19:36', 14),
(61, 'jkev', '2014-01-13 18:46:08', '2014-02-13 11:19:36', 14),
(62, 'jkev', '2014-01-15 20:40:15', '2014-02-13 11:19:36', 14),
(63, 'jkev', '2014-01-16 14:42:02', '2014-02-13 11:19:36', 14),
(64, 'jkev', '2014-01-17 09:16:17', '2014-02-13 11:19:36', 14),
(65, 'jkev', '2014-01-17 13:25:51', '2014-02-13 11:19:36', 14),
(66, 'admin', '2014-01-17 14:41:30', '2020-12-21 08:48:16', 15),
(67, 'admin', '2014-01-17 15:56:32', '2020-12-21 08:48:16', 15),
(68, 'admin', '2014-01-26 17:45:31', '2020-12-21 08:48:16', 15),
(69, 'admin', '2014-02-13 10:45:17', '2020-12-21 08:48:16', 15),
(70, 'admin', '2014-02-13 11:05:27', '2020-12-21 08:48:16', 15),
(71, 'jkev', '2014-02-13 11:16:48', '2014-02-13 11:19:36', 14),
(72, 'admin', '2014-02-13 11:55:36', '2020-12-21 08:48:16', 15),
(73, 'admin', '2014-02-13 12:32:38', '2020-12-21 08:48:16', 15),
(74, 'admin', '2014-02-13 12:52:05', '2020-12-21 08:48:16', 15),
(75, 'admin', '2014-02-13 13:04:35', '2020-12-21 08:48:16', 15),
(76, 'jkev', '2014-02-13 14:35:27', '', 14),
(77, 'admin', '2014-02-20 09:40:39', '2020-12-21 08:48:16', 15),
(78, 'admin', '2014-02-20 09:42:21', '2020-12-21 08:48:16', 15),
(79, 'admin', '2014-02-27 22:40:15', '2020-12-21 08:48:16', 15),
(80, 'admin', '2014-02-28 13:12:52', '2020-12-21 08:48:16', 15),
(81, 'admin', '2014-04-02 17:27:47', '2020-12-21 08:48:16', 15),
(82, 'admin', '2014-04-03 15:29:38', '2020-12-21 08:48:16', 15),
(83, 'admin', '2014-06-15 12:31:51', '2020-12-21 08:48:16', 15),
(84, 'Admin', '2020-12-21 08:32:51', '2020-12-21 08:48:16', 15),
(85, 'admin', '2020-12-21 08:48:23', '', 15),
(86, 'admin', '2024-02-23 21:20:53', '', 15);
--
-- Database: `dbgrading`
--
CREATE DATABASE IF NOT EXISTS `dbgrading` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `dbgrading`;

-- --------------------------------------------------------

--
-- Table structure for table `academicinfo`
--

DROP TABLE IF EXISTS `academicinfo`;
CREATE TABLE IF NOT EXISTS `academicinfo` (
  `AcadInfo` int NOT NULL AUTO_INCREMENT,
  `AY` varchar(11) NOT NULL,
  `Sem` varchar(11) NOT NULL,
  PRIMARY KEY (`AcadInfo`)
) ENGINE=MyISAM AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `academicinfo`
--

INSERT INTO `academicinfo` (`AcadInfo`, `AY`, `Sem`) VALUES
(1, '2021-2022', '1st');

-- --------------------------------------------------------

--
-- Table structure for table `tblacadinfo`
--

DROP TABLE IF EXISTS `tblacadinfo`;
CREATE TABLE IF NOT EXISTS `tblacadinfo` (
  `StdAcadID` int NOT NULL AUTO_INCREMENT,
  `StdID` int NOT NULL,
  `StdSec` varchar(255) NOT NULL,
  `StdYear` varchar(255) NOT NULL,
  `StdSem` varchar(255) NOT NULL,
  `StdAY` varchar(255) NOT NULL,
  `StdCourse` varchar(255) NOT NULL,
  `StdDept` varchar(255) NOT NULL,
  PRIMARY KEY (`StdAcadID`),
  KEY `StdID` (`StdID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `tblacadinfo`
--

INSERT INTO `tblacadinfo` (`StdAcadID`, `StdID`, `StdSec`, `StdYear`, `StdSem`, `StdAY`, `StdCourse`, `StdDept`) VALUES
(1, 14, 'BSIT 3D', '3rd', '1st', '2021-2022', 'Bachelor of Science in Information Technology', 'CSS');

-- --------------------------------------------------------

--
-- Table structure for table `tbladmin`
--

DROP TABLE IF EXISTS `tbladmin`;
CREATE TABLE IF NOT EXISTS `tbladmin` (
  `AdminID` int NOT NULL,
  `AdminUser` varchar(255) NOT NULL,
  `AdminPass` varchar(255) NOT NULL,
  `AdminEmail` varchar(255) NOT NULL,
  PRIMARY KEY (`AdminID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `tbladmin`
--

INSERT INTO `tbladmin` (`AdminID`, `AdminUser`, `AdminPass`, `AdminEmail`) VALUES
(1, 'admin', '$2y$10$xjvtajtdEur2Yt7.G.b6TOMMcPHOcoIQkmncGL7DzTkV4r5lUYBOC', 'admin@admin.com'),
(2, 'admin2', 'admin2', 'admin2@admin2.com');

-- --------------------------------------------------------

--
-- Table structure for table `tblcontact`
--

DROP TABLE IF EXISTS `tblcontact`;
CREATE TABLE IF NOT EXISTS `tblcontact` (
  `ContID` int NOT NULL AUTO_INCREMENT,
  `ContEmail` varchar(255) NOT NULL,
  `ContDesc` varchar(255) NOT NULL,
  PRIMARY KEY (`ContID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `tblgrades`
--

DROP TABLE IF EXISTS `tblgrades`;
CREATE TABLE IF NOT EXISTS `tblgrades` (
  `GradeID` int NOT NULL AUTO_INCREMENT,
  `SubID` int NOT NULL,
  `SubGrade` int NOT NULL DEFAULT '0',
  `GradeSem` varchar(255) NOT NULL,
  `GradeAY` varchar(255) NOT NULL,
  `ProfID` int NOT NULL,
  `StdID` int NOT NULL,
  PRIMARY KEY (`GradeID`),
  KEY `StdID` (`StdID`),
  KEY `ProfID` (`ProfID`),
  KEY `SubID` (`SubID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `tblprof`
--

DROP TABLE IF EXISTS `tblprof`;
CREATE TABLE IF NOT EXISTS `tblprof` (
  `ProfID` int NOT NULL AUTO_INCREMENT,
  `ProfUser` varchar(255) NOT NULL,
  `ProfPass` varchar(255) NOT NULL,
  `ProfEmail` varchar(255) NOT NULL,
  `ProfFName` varchar(255) NOT NULL,
  `ProfLName` varchar(255) NOT NULL,
  PRIMARY KEY (`ProfID`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `tblprof`
--

INSERT INTO `tblprof` (`ProfID`, `ProfUser`, `ProfPass`, `ProfEmail`, `ProfFName`, `ProfLName`) VALUES
(1, 'prof', '$2y$10$c7mE0fbbUbpMK9fSGyYsIOSLIqe5dhiiVuwtOEx5RUUkUfaiJiQ3G', 'faculty@faculty.com', 'Mar Eli', 'Sagsagat'),
(2, 'prof2', '$2y$10$fpJPk0C085qo6Es5XhebpOhlEQBk9JZKnHwxNJ40jnAY7I3vzwmSu', 'faculty2@faculty.com', 'Ana Marie', 'Obon'),
(3, 'prof3', '$2y$10$YsKVVIj5UT9qdxZ7mCCaMeO8LT/KXNgecwuHE2WIwb5DawW3uEG2W', 'faculty3@cityofmalabonuniversity.edu.ph', 'Nicolas', 'Cayetano '),
(4, 'prof4', '$2y$10$ecWf3OOSCbfO.1M4mmJaoueUBcJNpuHySajPgWFUZI/0i6qx1srja', 'faculty4@cityofmalabonuniversity.edu.ph', 'Jensen', 'Santillan'),
(5, 'prof5', '', 'faculty5@cityofmalabonuniversity.edu.ph', 'Elmer', 'Tamana'),
(6, 'prof6', '$2y$10$JMxkpJF/vVkfw.6QEMFBkevVvMXmRruQsHF6GTWn8ACK5nZ4iSO6a', '', 'Prof', 'Prof');

-- --------------------------------------------------------

--
-- Table structure for table `tblstd`
--

DROP TABLE IF EXISTS `tblstd`;
CREATE TABLE IF NOT EXISTS `tblstd` (
  `StdID` int NOT NULL AUTO_INCREMENT,
  `StdUser` varchar(255) NOT NULL,
  `StdPass` varchar(255) NOT NULL,
  `StdEmail` varchar(255) NOT NULL,
  `StdReg` int NOT NULL COMMENT '0 = Registered User\r\n1 = Official Student',
  PRIMARY KEY (`StdID`)
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `tblstd`
--

INSERT INTO `tblstd` (`StdID`, `StdUser`, `StdPass`, `StdEmail`, `StdReg`) VALUES
(14, '20200000', '$2y$10$WpwW7nT4NsQup.lTLSdQYuYOGNJ0.alRMsrr97ZCFDIcvqTOGdsfK', '20200881@cityofmalabonuniversity.edu.ph', 1);

-- --------------------------------------------------------

--
-- Table structure for table `tblstdinfo`
--

DROP TABLE IF EXISTS `tblstdinfo`;
CREATE TABLE IF NOT EXISTS `tblstdinfo` (
  `StdID` int NOT NULL,
  `StdFName` varchar(255) NOT NULL,
  `StdMName` varchar(255) NOT NULL,
  `StdLName` varchar(255) NOT NULL,
  `StdBday` date NOT NULL,
  `StdSex` varchar(255) NOT NULL,
  `StdStatus` varchar(255) NOT NULL,
  `StdHNo` varchar(255) NOT NULL,
  `StdStreet` varchar(255) NOT NULL,
  `StdBarangay` varchar(255) NOT NULL,
  `StdCity` varchar(255) NOT NULL,
  `StdZip` varchar(255) NOT NULL,
  UNIQUE KEY `StdID_2` (`StdID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `tblstdinfo`
--

INSERT INTO `tblstdinfo` (`StdID`, `StdFName`, `StdMName`, `StdLName`, `StdBday`, `StdSex`, `StdStatus`, `StdHNo`, `StdStreet`, `StdBarangay`, `StdCity`, `StdZip`) VALUES
(14, 'HENRY', 'ROBRIGADO', 'OLIVEROS', '2001-10-24', 'Male', 'TAKEN', '234', 'MATADOR', 'UBO', 'ENGOT', '1232');

-- --------------------------------------------------------

--
-- Table structure for table `tblsubinfo`
--

DROP TABLE IF EXISTS `tblsubinfo`;
CREATE TABLE IF NOT EXISTS `tblsubinfo` (
  `SubID` int NOT NULL AUTO_INCREMENT,
  `SubCode` varchar(255) NOT NULL,
  `SubName` varchar(255) NOT NULL,
  `SubUnit` int NOT NULL,
  `SubSec` varchar(255) NOT NULL,
  `SubSem` varchar(255) NOT NULL,
  `SubAY` varchar(255) NOT NULL,
  `ProfID` int NOT NULL,
  PRIMARY KEY (`SubID`),
  KEY `ProfID` (`ProfID`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `tblsubinfo`
--

INSERT INTO `tblsubinfo` (`SubID`, `SubCode`, `SubName`, `SubUnit`, `SubSec`, `SubSem`, `SubAY`, `ProfID`) VALUES
(1, 'ITE311', 'INTEGRATIVE PROGRAMMING AND TECHNOLOGY', 5, 'BSIT 3D', '1st', '2022-2023', 1),
(2, 'ITE312', 'SYSTEM INTEGRATION AND ARCHITECTURE 1', 3, 'BSIT 3D', '1st', '2022-2023', 2),
(3, 'ITE314', 'SYSTEM ANALYSIS AND DESIGN', 3, 'BSIT 3D', '1st', '2022-2023', 3),
(4, 'ITE315', 'PLATFORMS TECHNOLOGIES', 3, 'BSIT 3D', '1st', '2022-2023', 4);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `tblcontact`
--
ALTER TABLE `tblcontact` ADD FULLTEXT KEY `ContEmail` (`ContEmail`,`ContDesc`);

--
-- Constraints for dumped tables
--

--
-- Constraints for table `tblacadinfo`
--
ALTER TABLE `tblacadinfo`
  ADD CONSTRAINT `tblacadinfo_ibfk_1` FOREIGN KEY (`StdID`) REFERENCES `tblstd` (`StdID`);

--
-- Constraints for table `tblgrades`
--
ALTER TABLE `tblgrades`
  ADD CONSTRAINT `tblgrades_ibfk_1` FOREIGN KEY (`StdID`) REFERENCES `tblstd` (`StdID`),
  ADD CONSTRAINT `tblgrades_ibfk_2` FOREIGN KEY (`ProfID`) REFERENCES `tblprof` (`ProfID`),
  ADD CONSTRAINT `tblgrades_ibfk_3` FOREIGN KEY (`SubID`) REFERENCES `tblsubinfo` (`SubID`);

--
-- Constraints for table `tblstdinfo`
--
ALTER TABLE `tblstdinfo`
  ADD CONSTRAINT `tblstdinfo_ibfk_1` FOREIGN KEY (`StdID`) REFERENCES `tblstd` (`StdID`);

--
-- Constraints for table `tblsubinfo`
--
ALTER TABLE `tblsubinfo`
  ADD CONSTRAINT `tblsubinfo_ibfk_1` FOREIGN KEY (`ProfID`) REFERENCES `tblprof` (`ProfID`);
--
-- Database: `dbhofin`
--
CREATE DATABASE IF NOT EXISTS `dbhofin` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `dbhofin`;

-- --------------------------------------------------------

--
-- Table structure for table `tbl_face`
--

DROP TABLE IF EXISTS `tbl_face`;
CREATE TABLE IF NOT EXISTS `tbl_face` (
  `face_id` int NOT NULL AUTO_INCREMENT,
  `face_img` varchar(255) NOT NULL,
  PRIMARY KEY (`face_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tbl_property`
--

DROP TABLE IF EXISTS `tbl_property`;
CREATE TABLE IF NOT EXISTS `tbl_property` (
  `property_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `id_no` varchar(255) DEFAULT NULL,
  `blk_no` int DEFAULT NULL,
  `lot_no` int DEFAULT NULL,
  `homelot_area` int DEFAULT NULL,
  `open_space` int DEFAULT NULL,
  `sharein_loan` int DEFAULT NULL,
  `principal_interest` int DEFAULT NULL,
  `MRI` int DEFAULT NULL,
  `total` int DEFAULT NULL,
  PRIMARY KEY (`property_id`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `tbl_property`
--

INSERT INTO `tbl_property` (`property_id`, `user_id`, `id_no`, `blk_no`, `lot_no`, `homelot_area`, `open_space`, `sharein_loan`, `principal_interest`, `MRI`, `total`) VALUES
(1, 2, '1', 2, 3, 4, 5, 6, 7, 8, 9),
(2, 3, '20203', 9, 65, 97569, 57, 65, 756, 87, 6587),
(3, 4, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `tbl_transaction`
--

DROP TABLE IF EXISTS `tbl_transaction`;
CREATE TABLE IF NOT EXISTS `tbl_transaction` (
  `transac_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `balance_debt` int DEFAULT NULL,
  `transc_type` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `amount` int DEFAULT NULL,
  `date` date DEFAULT NULL,
  `due_date` date DEFAULT NULL,
  `is_verified` varchar(10) NOT NULL DEFAULT 'no',
  `code` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `proof` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  PRIMARY KEY (`transac_id`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `tbl_transaction`
--

INSERT INTO `tbl_transaction` (`transac_id`, `user_id`, `balance_debt`, `transc_type`, `amount`, `date`, `due_date`, `is_verified`, `code`, `proof`) VALUES
(1, 2, 3000, 'Cash', NULL, NULL, '2024-03-29', 'no', 'PRE2V', NULL),
(2, 3, 6, 'Cash', NULL, NULL, '2024-04-18', 'no', '8PD1S', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `tbl_useracc`
--

DROP TABLE IF EXISTS `tbl_useracc`;
CREATE TABLE IF NOT EXISTS `tbl_useracc` (
  `user_id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `is_admin` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'no',
  `is_deleted` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'no',
  `is_verified` varchar(10) NOT NULL DEFAULT 'no',
  PRIMARY KEY (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `tbl_useracc`
--

INSERT INTO `tbl_useracc` (`user_id`, `username`, `password`, `email`, `is_admin`, `is_deleted`, `is_verified`) VALUES
(1, 'admin', '$2b$12$lTwEqKy98rZhefz/lYFO7OFORY7F/NtPyTnnolKfInFsTojgl2ugO', '', 'yes', 'no', 'yes'),
(2, '20242', '$2b$12$92vMhEjqOTN/9wM92jsmgeTi9HRSs5Jo5TxYcbvAUzESCR2HyN/C2', 'jetsebastian4@gmail.com', 'no', 'no', 'yes'),
(3, '20243', '$2b$12$tB9bEdIZlyt08mTJmyI1gOmTYR72q/sA0C9N7nGTvjykBAtG4n8MK', 'agajdbualal@gmail.com', 'no', 'no', 'yes'),
(4, '20244', '$2b$12$Qm6FwOLLAjh8gSzm0d3/Vu8vpvWZxyD8d8kO8ARjpJtNl2ZKUjBfi', 'asdasd@asdasd.asdasd', 'no', 'no', 'yes');

-- --------------------------------------------------------

--
-- Table structure for table `tbl_userinfo`
--

DROP TABLE IF EXISTS `tbl_userinfo`;
CREATE TABLE IF NOT EXISTS `tbl_userinfo` (
  `userinfo_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `given_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `middle_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `last_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `gender` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  PRIMARY KEY (`userinfo_id`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `tbl_userinfo`
--

INSERT INTO `tbl_userinfo` (`userinfo_id`, `user_id`, `given_name`, `middle_name`, `last_name`, `gender`) VALUES
(1, 1, 'Admin', '', '', ''),
(2, 2, 'Jet', 'Dela cruz', 'Sebastian', 'Male'),
(3, 3, 'John andrei', 'Samonte', 'Canlas', 'Male'),
(4, 4, 'A', 'B', 'C', 'Male');

--
-- Constraints for dumped tables
--

--
-- Constraints for table `tbl_property`
--
ALTER TABLE `tbl_property`
  ADD CONSTRAINT `tbl_property_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `tbl_useracc` (`user_id`) ON DELETE RESTRICT ON UPDATE RESTRICT;

--
-- Constraints for table `tbl_transaction`
--
ALTER TABLE `tbl_transaction`
  ADD CONSTRAINT `tbl_transaction_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `tbl_useracc` (`user_id`) ON DELETE RESTRICT ON UPDATE RESTRICT;

--
-- Constraints for table `tbl_userinfo`
--
ALTER TABLE `tbl_userinfo`
  ADD CONSTRAINT `tbl_userinfo_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `tbl_useracc` (`user_id`) ON DELETE RESTRICT ON UPDATE RESTRICT;
--
-- Database: `db_auth`
--
CREATE DATABASE IF NOT EXISTS `db_auth` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `db_auth`;

-- --------------------------------------------------------

--
-- Table structure for table `members`
--

DROP TABLE IF EXISTS `members`;
CREATE TABLE IF NOT EXISTS `members` (
  `member_id` int NOT NULL AUTO_INCREMENT,
  `member_name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL,
  `member_password` varchar(64) NOT NULL,
  `member_email` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL,
  PRIMARY KEY (`member_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `members`
--

INSERT INTO `members` (`member_id`, `member_name`, `member_password`, `member_email`) VALUES
(1, 'admin', '$2a$10$0FHEQ5/cplO3eEKillHvh.y009Wsf4WCKvQHsZntLamTUToIBe.fG', 'user@gmail.com');

-- --------------------------------------------------------

--
-- Table structure for table `tbl_token_auth`
--

DROP TABLE IF EXISTS `tbl_token_auth`;
CREATE TABLE IF NOT EXISTS `tbl_token_auth` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `selector_hash` varchar(255) NOT NULL,
  `is_expired` int NOT NULL DEFAULT '0',
  `expiry_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=latin1;
--
-- Database: `detection`
--
CREATE DATABASE IF NOT EXISTS `detection` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `detection`;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
CREATE TABLE IF NOT EXISTS `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `full_name` varchar(128) COLLATE utf8mb4_general_ci NOT NULL,
  `user_name` varchar(128) COLLATE utf8mb4_general_ci NOT NULL,
  `password` varchar(128) COLLATE utf8mb4_general_ci NOT NULL,
  `pic` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `full_name`, `user_name`, `password`, `pic`) VALUES
(1, 'ken', 'ken', '$2y$10$K/qfuNf7XEAfkNmz8w8ChOSaGpkR3rO9omXA9KBriNuoP1fO1UBfa', ''),
(2, 'asdasdasdasd', 'admin', '$2y$10$SKFIagl/a/ce.l/XwWkYZuRzikprWUbL1RKGryb79hbu6dVgUibha', 'upload/2.png');
--
-- Database: `enrollment`
--
CREATE DATABASE IF NOT EXISTS `enrollment` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `enrollment`;

-- --------------------------------------------------------

--
-- Table structure for table `course`
--

DROP TABLE IF EXISTS `course`;
CREATE TABLE IF NOT EXISTS `course` (
  `course_id` varchar(20) NOT NULL,
  `instructor_id` int DEFAULT NULL,
  `course_name` varchar(100) DEFAULT NULL,
  `course_details` varchar(300) DEFAULT NULL,
  PRIMARY KEY (`course_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `course`
--

INSERT INTO `course` (`course_id`, `instructor_id`, `course_name`, `course_details`) VALUES
('DAA 430C', 1, 'Design and Analysis of Algorithms', 'Learn Algorithms and their design and analysis as to their efficiency'),
('IPPL 422C', 2, 'Principles of programming languages', 'Learn syntax and semantics of programming languages'),
('IDBM 432C', 3, 'Database Management System', 'Learn Database Management System design and concepts'),
('SPAS 430C', 4, 'Probability And Statistics', 'Learn fundamentals of Probability And Statistics'),
('EPOC 432C', 5, 'Principles Of Communication', 'Learn how communication systems work'),
('IOOM 332C', 6, 'Object Oriented Methodologies', 'Learn OOM concepts with Java'),
('IOPS 332C', 7, 'Operating Systems', 'Learn Operating System concepts'),
('ITOC 330C', 8, 'Theory Of Computation', 'Learn about Theory Of Computation and Automata'),
('SMAT 330C', 9, 'Mathematics-3', 'Learn Complex Analysis and Transformations'),
('EMIP 332C', 10, 'Microprocessors', 'Learn Microprocessor Interfacing and Programming'),
('IDSA 232C', 11, 'Data Structures And Algorithms', 'Learn Data Structures and Algorithms'),
('ICOA 230C', 12, 'Computer Organization And Architecture', 'Learn fundamentals of Computer Organization And Architecture'),
('IDIM 230C', 8, 'Discrete Mathematics', 'Learn concepts of Discrete Mathematics'),
('SMAT 232C', 13, 'Mathematics-2', 'Learn about Linear Algebra and Interpolation Techniques'),
('EDLE 232C', 5, 'Digital Electronics', 'Learn concepts of Digital Electronics'),
('ITP 232C', 15, 'Introduction To Programming', 'Learn how to program in a language like C'),
('ITC 232C', 16, 'Introduction To Computers', 'Learn basic concepts of a computer system'),
('EEDC 232C', 17, 'Electronic Devices And Circuits', 'Learn basic concepts of electronics like diode, transistor, oscillator, op amp etc.'),
('SMAT 230C', 18, 'Mathematics-1', 'Learn about Ordinary Differential Equations, Sequences and Series, A brief introduction to Multivariable Calculus'),
('ECAS 230C', 10, 'Circuit Analysis And Synthesis', 'Learn fundamentals of circuit theory'),
('ICNW 532C', 19, 'Computer Networks', 'Learn how computer network works'),
('ISWE 532C', 20, 'Software Engineering', 'Learn how to build quality softwares'),
('IAIN 532C', 21, 'Artificial Intelligence', 'Learn how to use Artificial Intelligence in computers'),
('ICOG 532C', 22, 'Computer Graphics', 'Learn how Computer Graphics work'),
('MPOE 530C', 23, 'Principles Of Economics', 'Learn about basic Principles of Economics'),
('ICOD 632C', 15, 'Compiler Designing', 'Learn how to build a compiler for a language'),
('IDMW 632C', 24, 'Data Mining', 'Learn about concepts of Data Mining'),
('IOOT 630E', 25, 'Optimization Technologies', 'Learn about Optimization Techniques and how to apply them'),
('IIVP 632C', 26, 'Image and Voice Processing', 'Learn how Computer processes images and voice'),
('INLP 630E', 27, 'Natural Language Processing', 'Learn how is natural language processed'),
('IE1 7', 1, 'Elective 1', 'Learn about chosen Elective 1'),
('IE2 7', 28, 'Elective 2', 'Learn about chosen Elective 2'),
('IMP 7', 29, 'Mini Project', 'Project Evaluation'),
('IE1 8', 30, 'Elective 1', 'Learn about chosen Elective 1'),
('IE2 8', 2, 'Elective 2', 'Learn about chosen Elective 2'),
('IMP 8', 20, 'Mini Project', 'Project Evaluation'),
('ITP 132C', 15, 'Introduction To Programming', 'Learn how to program in a language like C'),
('ITC 132C', 14, 'Engineering Physics', 'Learn basic electrical concepts and classical and quantum mechanics'),
('EEDC 132C', 17, 'Electronic Devices And Circuits', 'Learn basic concepts of electronics like diode, transistor, oscillator, op amp etc.'),
('SMAT 130C', 18, 'Mathematics-1', 'Learn about Ordinary Differential Equations, Sequences and Series, A brief introduction to Multivariable Calculus'),
('ECAS 130C', 10, 'Circuit Analysis And Synthesis', 'Learn fundamentals of circuit theory'),
('EDES 232C', 14, 'Digital Electronics', 'Introduction to components and logical design of a Electronic Circuit'),
('IDMS 230C', 8, 'Discrete Mathematics', 'Learn logic calculus and appropriate techniques of proofs'),
('IDST 232C', 11, 'Data Structures', 'Learn about the basic data structures needed to build complex programs'),
('SPAS 230C', 4, 'Probability And Statistics', 'Learn fundamentals of Probability And Statistics'),
('MPOM 230C', 44, 'Principles of Management', 'Get acquainted with the basic principles of management'),
('IOSY 332C', 7, 'Operating System', 'Learn the inner workings behind an Operating System'),
('EAES 332C', 43, 'Analog Electronics', 'Learn about the components required to build an analog circuit'),
('EACN 332C', 5, 'Analog Communication', 'Learn about signals, their modulation techniques and noise'),
('EEFW 330C', 36, 'Electromagnetic Fields and Waves', 'Learn about Electrostatics, Magnetostatics and application of waves'),
('EBEE 330C', 17, 'Basic Electrical Engineering', 'Learn about the components of a AC or DC circuit'),
('MMAM 420F', 44, 'Marketing Management', 'Learn how to program in a language like C'),
('ESAS 430C', 34, 'Discrete Time Signals and Systems', 'Learn about Signals and Systems and their discrete time fourier series and transforms and Z-tranforms'),
('EMIP 432C', 10, 'Microprocessor Interface and Programming', 'Learn Microprocessor Interfacing and Programming'),
('EEMI 432C', 35, 'Electronics Measurement and Instrumentation', 'Learn about Instruments needed for measurements'),
('EICT 430C', 17, 'Integrated Circuits Technology', 'Learn how to synthesize an integrated circuit'),
('EICT 432C', 35, 'Microwave Engineering', 'Learn about micro waves'),
('EDCN 532C', 46, 'Digital Communication', 'Learn about Digital Signals and their modulation techniques'),
('ECSY 532C', 45, 'Control Systems', 'Introduction to Control Systems'),
('ECNW 532C', 39, 'Computer Networks', 'Learn about Computer Networks'),
('EAWP 532C', 35, 'Antenna and Wave Propagation', 'Learn Antenna theory and behaviour of waves'),
('MMEC 520F', 44, 'Managerial Economics', 'Learn about Economics involved in management'),
('EPOP 503P', 5, 'Project Oriented Practices', 'Group Project'),
('EOCN 632C', 5, 'Optical Communication', 'Learn about opticla communication'),
('EVSD 632C', 36, 'VLSI System Design', 'Learn to design a functioning VLSI system'),
('EDSP 632C', 43, 'Digital Signal Processing', 'Learn basic concepts of processing a digital signal'),
('Elective 1', 10, 'Elective 1', 'Elective 1'),
('Elective 2', 17, 'Elective 2', 'Elective 2'),
('EGPJ 604P', 35, 'Group Project', 'Group Project'),
('EESD 732C', 17, 'Embedded System Design', 'Learn to design an embedded system'),
('EWCN 732C', 5, 'Wireless Communication', 'Learn basic concepts of wireless communication'),
('Elective 3', 10, 'Elective 3', 'Elective 3'),
('Elective 4', 17, 'Elective 4', 'Elective 4'),
('Elective 5', 35, 'Elective 5', 'Elective 5'),
('EGPJ 706P', 34, 'Group Project', 'Group Project'),
('EPRJ 802P', 5, 'Individual Project', 'Individual Project');

-- --------------------------------------------------------

--
-- Table structure for table `course_allotted`
--

DROP TABLE IF EXISTS `course_allotted`;
CREATE TABLE IF NOT EXISTS `course_allotted` (
  `programme` varchar(20) DEFAULT NULL,
  `department` varchar(60) DEFAULT NULL,
  `semester` int DEFAULT NULL,
  `course_id` varchar(20) DEFAULT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `course_allotted`
--

INSERT INTO `course_allotted` (`programme`, `department`, `semester`, `course_id`) VALUES
('B.Tech', 'I.T', 4, 'DAA 430C'),
('B.tech', 'I.T', 4, 'IPPL 422C'),
('B.tech', 'I.T', 4, 'IPPL 430C'),
('B.tech', 'I.T', 4, 'IDBM 432C'),
('B.tech', 'I.T', 4, 'SPAS 430C'),
('B.tech', 'I.T', 4, 'EPOC 432C'),
('B.tech', 'I.T', 3, 'IOOM 332C'),
('B.tech', 'I.T', 3, 'IOPS 332C'),
('B.tech', 'I.T', 3, 'ITOC 330C'),
('B.tech', 'I.T', 3, 'SMAT 330C'),
('B.tech', 'I.T', 3, 'EMIP 332C'),
('B.tech', 'I.T', 2, 'IDSA 232C'),
('B.tech', 'I.T', 2, 'ICOA 230C'),
('B.tech', 'I.T', 2, 'IDIM 230C'),
('B.tech', 'I.T', 2, 'SMAT 232C'),
('B.tech', 'I.T', 2, 'EDLE 232C'),
('B.tech', 'I.T', 1, 'ITP 132C'),
('B.tech', 'I.T', 1, 'ITC 132C'),
('B.tech', 'I.T', 1, 'EEDC 132C'),
('B.tech', 'I.T', 1, 'SMAT 130C'),
('B.tech', 'I.T', 1, 'ECAS 130C'),
('B.tech', 'I.T', 5, 'ICNW 532C'),
('B.tech', 'I.T', 5, 'ISWE 532C'),
('B.tech', 'I.T', 5, 'IAIN 532C'),
('B.tech', 'I.T', 5, 'ICOG 532C'),
('B.tech', 'I.T', 5, 'MPOE 532C'),
('B.tech', 'I.T', 6, 'ICOD 632C'),
('B.tech', 'I.T', 6, 'IDMW 632C'),
('B.tech', 'I.T', 6, 'IOOT 630E'),
('B.tech', 'I.T', 6, 'IIVP 632C'),
('B.tech', 'I.T', 6, 'INLP 630E'),
('B.tech', 'I.T', 7, 'IE1'),
('B.tech', 'I.T', 7, 'IE2'),
('B.tech', 'I.T', 7, 'IMP'),
('B.tech', 'I.T', 8, 'IE1'),
('B.tech', 'I.T', 8, 'IE2'),
('B.tech', 'I.T', 8, 'IMP'),
('B.tech', 'E.C.E', 1, 'IIPG 132C'),
('B.tech', 'E.C.E', 1, 'SEGP 132C'),
('B.tech', 'E.C.E', 1, 'EEDC 132C'),
('B.tech', 'E.C.E', 1, 'SCDE 130C'),
('B.tech', 'E.C.E', 1, 'ECAS 130C'),
('B.tech', 'E.C.E', 1, 'ITC 132C'),
('B.tech', 'E.C.E', 2, 'EDES 232C'),
('B.tech', 'E.C.E', 2, 'IDMS 230C'),
('B.tech', 'E.C.E', 2, 'IDST 232C'),
('B.tech', 'E.C.E', 2, 'SPAS 230C'),
('B.tech', 'E.C.E', 2, 'ICOA 230C'),
('B.tech', 'E.C.E', 2, 'MPOM 230C'),
('B.tech', 'E.C.E', 3, 'IOSY 332C'),
('B.tech', 'E.C.E', 3, 'EAES 332C'),
('B.tech', 'E.C.E', 3, 'EACN 332C'),
('B.tech', 'E.C.E', 3, 'EEFW 330C'),
('B.tech', 'E.C.E', 3, 'EBEE 332C'),
('B.tech', 'E.C.E', 4, 'MMAM 420F'),
('B.tech', 'E.C.E', 4, 'ESAS 430C'),
('B.tech', 'E.C.E', 4, 'EMIP 432C'),
('B.tech', 'E.C.E', 4, 'EEMI 432C'),
('B.tech', 'E.C.E', 4, 'EICT 430C'),
('B.tech', 'E.C.E', 4, 'EMWE 432C'),
('B.tech', 'E.C.E', 5, 'EDCN 532C'),
('B.tech', 'E.C.E', 5, 'ECSY 532C'),
('B.tech', 'E.C.E', 5, 'ECNW 532C'),
('B.tech', 'E.C.E', 5, 'EAWP 532C'),
('B.tech', 'E.C.E', 5, 'MMEC 520F'),
('B.tech', 'E.C.E', 5, 'EPOP 503P'),
('B.tech', 'E.C.E', 6, 'EOCN 632C'),
('B.tech', 'E.C.E', 6, 'EVSD 632C'),
('B.tech', 'E.C.E', 6, 'EDSP 632C'),
('B.tech', 'E.C.E', 6, 'Elective 1'),
('B.tech', 'E.C.E', 6, 'Elective 2'),
('B.tech', 'E.C.E', 6, 'EGPJ 604P'),
('B.tech', 'E.C.E', 7, 'EESD 732C'),
('B.tech', 'E.C.E', 7, 'EWCN 732C'),
('B.tech', 'E.C.E', 7, 'Elective 3'),
('B.tech', 'E.C.E', 7, 'Elective 4'),
('B.tech', 'E.C.E', 7, 'Elective 5'),
('B.tech', 'E.C.E', 7, 'EGPJ 706P'),
('B.tech', 'ECE', 8, 'EPRJ 802P');

-- --------------------------------------------------------

--
-- Table structure for table `instructor`
--

DROP TABLE IF EXISTS `instructor`;
CREATE TABLE IF NOT EXISTS `instructor` (
  `instructor_id` int DEFAULT NULL,
  `instructor_name` varchar(60) DEFAULT NULL,
  `contact_email` varchar(30) DEFAULT NULL,
  `profile_link` varchar(60) DEFAULT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `instructor`
--

INSERT INTO `instructor` (`instructor_id`, `instructor_name`, `contact_email`, `profile_link`) VALUES
(1, 'Amit Dhar', 'amit@iiita.ac.in', 'http://profile.iiita.ac.in/amitdhar'),
(2, 'Jagpreet Singh', 'jagp@iiita.ac.in', 'http://profile.iiita.ac.in/jagpreets'),
(3, 'Amrita Chaturvedi', 'amrita@iiita.ac.in', 'http://profile.iiita.ac.in/amrita'),
(4, 'Sumit Kumar Upadhyay', 'upsumit@iiita.ac.in', 'http://profile.iiita.ac.in/upsumit'),
(5, 'Niteesh Purohit', 'np@iiita.ac.in', 'http://profile.iiita.ac.in/np|suneel|somakb'),
(6, 'Ranjana Vyas', 'ranjana@iiita.ac.in', 'http://profile.iiita.ac.in/ranana'),
(7, 'Bibhas Ghoshal', 'bibhas.ghoshal@iiita.ac.in', 'http://profile.iiita.ac.in/bibhas.ghoshal'),
(8, 'Somenath Biswas', 'sb@iiita.ac.in', 'http://profile.iiita.ac.in/sb'),
(9, 'Abdullah Bin Abu Baker', 'abdullah@iiita.ac.in', 'http://profile.iiita.ac.in/abdullah'),
(10, 'Prasanna Kumar Misra', 'prasanna@iiita.ac.in', 'http://profile.iiita.ac.in/prasanna'),
(11, 'Sonali Agarwal', 'sonali@iiita.ac.in', 'http://profile.iiita.ac.in/sonali'),
(12, 'Satish Kumar Singh', 'sk.singh@iiita.ac.in', 'http://profile.iiita.ac.in/sk.singh'),
(13, 'Akhilesh Tiwari', 'atiwari@iiita.ac.in', 'http://profile.iiita.ac.in/atiwari'),
(14, 'Pramod Kumar', 'pkumar@iiita.ac.in', 'http://profile.iiita.ac.in/pkumar'),
(15, 'Venkatesan S', 'venkat@iiita.ac.in', 'http://profile.iiita.ac.in/venkat'),
(16, 'Mithilesh Mishra', 'mithilesh@iiita.ac.in', 'http://profile.iiita.ac.in/mithilesh'),
(17, 'Sitangshu Bhattacharya', 'sitangshu@iiita.ac.in', 'http://profile.iiita.ac.in/sitangshu'),
(18, 'Ramji Lal', 'ramji@iiita.ac.in', 'http://profile.iiita.ac.in/ramji'),
(19, 'Shekhar Verma', 'sverma@iiita.ac.in', 'http://profile.iiita.ac.in/sverma'),
(20, 'Sudip Sanyal', 'ssanyal@iiita.ac.in', 'http://profile.iiita.ac.in/ssanyal'),
(21, 'Rahul Kala', 'rkala@iiita.ac.in', 'http://profile.iiita.ac.in/rkala'),
(22, 'Pavan Chakraborty', 'pavan@iiita.ac.in', 'http://profile.iiita.ac.in/pavan'),
(23, 'Shailendra Kumar', 'shailendrak@iiita.ac.in', 'http://profile.iiita.ac.in/shailendrak'),
(24, 'Manish Kumar', 'manish@iiita.ac.in', 'http://profile.iiita.ac.in/manish'),
(25, 'Vrijendra Singh', 'vrij@iiita.ac.in', 'http://profile.iiita.ac.in/vrij'),
(26, 'U. S. Tiwary', 'ust@iiita.ac.in', 'http://profile.iiita.ac.in/ust'),
(27, 'Ratna Sanyal', 'rsanyal@iiita.ac.in', 'http://profile.iiita.ac.in/rsanyal'),
(28, 'Sanjeev B. S.', 'sanjeev@iiita.ac.in', 'https://iws44.iiita.ac.in/bss/website'),
(29, 'O. P. Vyas', 'opvyas@iiita.ac.in', 'http://profile.iiita.ac.in/opvyas'),
(30, 'Rahul Kala', 'rkala@iiita.ac.in', 'http://profile.iiita.ac.in/rkala'),
(31, 'Sunny Sharma', 'sunnys@iiita.ac.in', 'http://profile.iiita.ac.in/venkat'),
(32, 'Dr. K. P. Singh', 'kpsingh@iiita.ac.in', 'http://profile.iiita.ac.in/kpsingh'),
(33, 'Dr. Manish Goswami', 'manishgoswami@iiita.ac.in', 'http://profile.iiita.ac.in/manishgoswami'),
(34, 'Ms. Pooja Jain', 'poojajain@iiita.ac.in', 'http://profile.iiita.ac.in/poojajain'),
(35, 'Dr.Somak-Bhattacharyya', 'somakb@iiita.ac.in', 'http://profile.iiita.ac.in/somakb'),
(36, 'Dr. Rajat Kumar Singh', 'rajatsingh@iiita.ac.in', 'http://profile.iiita.ac.in/rajatsingh'),
(37, 'Dr. Vrijendra Singh', 'vrij@iiita.ac.in', 'http://profile.iiita.ac.in/vrij'),
(38, 'Dr. Anupam', 'anupam@iiita.ac.in', 'http://profile.iiita.ac.in/anupam'),
(39, 'Dr. Vijay K. Chaurasiya', 'vijayk@iiita.ac.in', 'http://profile.iiita.ac.in/vijayk'),
(40, 'Prof. G. C. Nandi', 'gcnandi@iiita.ac.in', 'http://profile.iiita.ac.in/gcnandi'),
(41, 'Dr. Ranjit Singh', '	ranjitsingh@iiita.ac.in', 'http://profile.iiita.ac.in/ranjitsingh'),
(42, 'Dr. Shirshu Varma', 'shirshu@iiita.ac.in', 'http://profile.iiita.ac.in/shirshu'),
(43, 'Dr. Rekha Verma', 'r.verma@iiita.ac.in', 'http://profile.iiita.ac.in/r.verma'),
(44, 'Dr. Vijayshri Tewari', 'vijayshri@iiita.ac.in', 'http://profile.iiita.ac.in/vijayshri'),
(45, 'Dr. Arun Kant Singh', 'aks@iiita.ac.in', 'http://profile.iiita.ac.in/aks'),
(46, 'Dr. Abhishek Vaish', 'abhishek@iiita.ac.in', 'http://profile.iiita.ac.in/abhishek');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
CREATE TABLE IF NOT EXISTS `users` (
  `rollno` varchar(60) NOT NULL,
  `fname` varchar(60) DEFAULT NULL,
  `lname` varchar(60) DEFAULT NULL,
  `sex` varchar(10) DEFAULT NULL,
  `date_dob` varchar(5) DEFAULT NULL,
  `month_dob` varchar(5) DEFAULT NULL,
  `year_dob` varchar(10) DEFAULT NULL,
  `father` varchar(60) DEFAULT NULL,
  `mother` varchar(60) DEFAULT NULL,
  `contact_number` varchar(20) DEFAULT NULL,
  `address_1` varchar(60) DEFAULT NULL,
  `address_2` varchar(60) DEFAULT NULL,
  `address_3` varchar(60) DEFAULT NULL,
  `category` varchar(10) DEFAULT NULL,
  `department` varchar(60) DEFAULT NULL,
  `programme` varchar(20) DEFAULT NULL,
  `batch` varchar(10) DEFAULT NULL,
  `semester` int DEFAULT NULL,
  `PASSWORD` varchar(128) DEFAULT NULL,
  `regdate` varchar(60) DEFAULT NULL,
  PRIMARY KEY (`rollno`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
--
-- Database: `face_login`
--
CREATE DATABASE IF NOT EXISTS `face_login` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `face_login`;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
CREATE TABLE IF NOT EXISTS `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `hash` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `hash`) VALUES
(1, 'admin', '$2b$12$3YMgbl9UL2XQM9OtuCKm.emPQdR7C28/kcREsSQXzErdaMw4t/dvC'),
(2, 'swa', '$2b$12$3YMgbl9UL2XQM9OtuCKm.emPQdR7C28/kcREsSQXzErdaMw4t/dvC'),
(3, 'admin123', '$2b$12$3YMgbl9UL2XQM9OtuCKm.emPQdR7C28/kcREsSQXzErdaMw4t/dvC'),
(4, 'admin111', '$2b$12$LyKegoTNMlYQ8wGMTAKFOeP58M3Xk3pSnoe6foCaNnWCEl146QSPm');
--
-- Database: `face_recognition`
--
CREATE DATABASE IF NOT EXISTS `face_recognition` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `face_recognition`;

-- --------------------------------------------------------

--
-- Table structure for table `tbl_attendrec`
--

DROP TABLE IF EXISTS `tbl_attendrec`;
CREATE TABLE IF NOT EXISTS `tbl_attendrec` (
  `attendance_id` int NOT NULL AUTO_INCREMENT,
  `employee_id` int NOT NULL,
  `full_name` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `date` date DEFAULT NULL,
  `time_in` time NOT NULL,
  `time_out` time DEFAULT NULL,
  PRIMARY KEY (`attendance_id`),
  KEY `employee_id` (`employee_id`)
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `tbl_attendrec`
--

INSERT INTO `tbl_attendrec` (`attendance_id`, `employee_id`, `full_name`, `date`, `time_in`, `time_out`) VALUES
(18, 45, 'Mark Louis Bernardo', '2024-01-27', '20:43:41', '21:23:38');

-- --------------------------------------------------------

--
-- Table structure for table `tbl_empdata`
--

DROP TABLE IF EXISTS `tbl_empdata`;
CREATE TABLE IF NOT EXISTS `tbl_empdata` (
  `employee_id` int NOT NULL AUTO_INCREMENT,
  `first_name` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `last_name` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `face_image` longblob,
  PRIMARY KEY (`employee_id`)
) ENGINE=InnoDB AUTO_INCREMENT=50 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `tbl_empdata`
--

INSERT INTO `tbl_empdata` (`employee_id`, `first_name`, `last_name`, `face_image`) VALUES
(45, 'Mark Louis', 'Bernardo', 0xffd8ffe000104a46494600010100000100010000ffe201d84943435f50524f46494c45000101000001c86c636d73021000006d6e74725247422058595a2007e2000300140009000e001d616373704d53465400000000736177736374726c0000000000000000000000000000f6d6000100000000d32d68616e649d91003d4080b03d40742c819ea5228e000000000000000000000000000000000000000000000000000000000000000964657363000000f00000005f637072740000010c0000000c7774707400000118000000147258595a0000012c000000146758595a00000140000000146258595a00000154000000147254524300000168000000606754524300000168000000606254524300000168000000606465736300000000000000057552474200000000000000000000000074657874000000004343300058595a20000000000000f35400010000000116c958595a200000000000006fa0000038f20000038f58595a2000000000000062960000b789000018da58595a2000000000000024a000000f850000b6c463757276000000000000002a0000007c00f8019c0275038304c9064e08120a180c620ef411cf14f6186a1c2e204324ac296a2e7e33eb39b33fd646574d3654765c17641d6c8675567e8d882c92369caba78cb2dbbe99cac7d765e477f1f9ffffffdb0043000604040504040605050506060607090e0909080809120d0d0a0e1512161615121414171a211c17181f1914141d271d1f2223252525161c292c28242b21242524ffdb00430106060609080911090911241814182424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424ffc000110803c003b603012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00f40db46deb451599a076a5fbab49b68fbdf2e68016978f5a4e7eed1bbe6a042eda5a4e691680179cd0d8a3fd9a5a003d28e7751fc547f15002f14522d1400ad46da4a552680168a4a5a0028c15a29d412148c2968a0028a28f4a005a6be73ba968edd680136fcb443d0d0b48a76bd30265a1976d2734ea004a5a28fbd8a005a1bfd9a1a85a0029d48b4ab4084db4b8a169d40094714bfc347140094b49feed3e801b452eda1a8013f868a751400514668e280131b734b4714b5402514bb68db4008d4bb68029680138c50d4b45002514b4605002514b450025253b1450027dea638e0d4951cdf70d00361fb838a0fdf14e897f7629bb3e7140128e828db47dda1a81098a297b51da800a4e7752d1400946deb4ea4f5a004a1a9692800a28a2800a663e6a7d26da004a4c7cd4fe3751400c5a181a5fbb47fb38a004ef4352d379a004ff0066929d4500230a36d1ba968005069ad4ea2801b8a377cb462918d0027ad1432d2b0a004fe1a296971400dfbb47f0eea4fbcd4ab40051454726766da0068cc8e5bf869ed422ed1b69557736ea00555db8a56a5a2801291695a8fbb8a00291a97348b400b45230a5a0046a3d68ff0074535a80173473494bceda0032686a314500028a46a2802b7dea5c7cd452d666c2514ac38a31ba8109452faad1fc540067750b4ad4b400dfbb42d3a936d02168a28fe1a005a4a29698094b4b46ca0016856dd48d4aab400ea29b4ab4006ea00eb4b45001450d4b4120050d4014b400ce54d23fde0d4e61f35235004b4ab4c43f253e800a28db4b8a0028c518a5dbf350160db4edb463a73450014bf76931f2d2d00145142b5310ea293752d03114d2d145002d251435020e28e2976d14006ddb4b8a4a5ddfc340094b452b500346696976d2d00378a29d4da0028fe2a3147dda003f0a56eb476a1a80168a2938aa00db515c7cc95254537f0d002efdbf2d2afccc6abc596b99370f956aca2d003b8a4a76da5a006b514ad40fba280169b4bb69281051433734714009ba86146da306800a1a9cc29306801acbc514ac2917140071450f49b4d0036969d4dc5001452eda36d00368a5dbf2d25001b69295a9bb7750038aeea6b77a5c518a006d26053e936d0026286c52afcb46def4009b7e5a283fdda306801b4b463f868db400545f7e5ff769f2fca9f76902ed4a0056f969c05357a96a7b2d0485336eea728346da0a12976d149400527ddef4ad49ff0001a090fbd4b45379a0056a6b014ad9a3f8a801b52537f0a28285e28edf35252377a003068a1738a28020a4c7cb4ad40f96b3360dbfc547dda285a0421c51ce695a979a003b52d26d38a3bd310714b45235000b4ad42ad1f7a80179e68a4fbb4b40052d26ea5a0028a3f868a003ef53a916969921451450014bcd253b140094b4629476ff0066801af498a7b00d4d5ceda0021e856a4a887cae7fdaa9a801568da7346da39a040b4e1f7a917ef51400bda96928e2800fbad4e5a6fad2d003a8a4db49fc5400bde9d4cddf2d2a9a005a5a6f6a764d00145273ba9cb5401471f7a8a2800a17ad14ea0028a28a0028a28a001968a314628013d297eed1450018db47af1452d002514b49400544f8dc2a5e1aa37fbf400c440b2b353e35348bf329a913a0a005a4e696856a004fe2fbb42d2d140051451400da29d45003714ea28a0028a6ab51400ea6e286a1734009494b450026d3f768c52d1f7a8011a919452f348df4a005a4db476a5a0436936d3e936fcb400df4a5a56a4f5a004f5a29168c5000b452d1f7b1400cc53a8a280136d2d14c95f68a00616dd2ff00bb4ea400aad2a2d002ad2e3e614ea2801ad42d1f796866a0045a181a4a5e73f2d0022b1cd145140ac0cd4518db45030a28a6f1400ea6d3a9bc500250d4b49b79eb4002d142d14015f752d252d666a1451462801db86de94522f5db4b400da77f15149f75a80168a4ef4b4085a148a4a168014628db451de801686c5142d000b4bb6969bfc5400ea286a2980b47147dda2800a7d373435003a80bb69172b4ab4122d47b7e63520efc535c7cd400c7f970d532d44577253e360c828024e28c514734c02976f5a1695734084a2968a0029d451b7e5a003d68a3d28a0046a368a5a46a005a31b6976d1400aab4628fe1a5db4006d2b46da3751de800db4b451400518a5a4a00314a57e6a168db40051451f76a804c518a5a5a004a5c50df4a5ed400d5ef46da5a280136d46df33d48d4c4f989a006e3daa55ed4d6a7d48032d2377a555a3fdeaa10d55a16968a0046cd2d2fe149da80128a5a4a0038a1a8a38a00293bd2ff000d1f8500368dbf2d3b1fdda2801b462976d2714005252ff1526da004c514bb6971400da2968a004a297ef52350014c6a7d3680136d14b450026da36d2d2350014351ba93f8a8005a84fccffeed4aedb54b54710dabf35002b53c2ed14d55f9b753ff000a004ddf35253a9bfc540094352d21c5000051451f76801286a0fcb450014dc8a71f985368005a46fbdbb341ff00668d940099a5db4aabcd0d8a002938a28fc2800a28a2802b714eedd2938a56fba2b3360e1a954d27142d002f346da1696801370a5a4db46ea042fdda3f8a93bd3a8100c714714945002b0fe2a28a298052ae68a75160136d0b494aa68b00bdfe5a5c7cb499a33400b8f9a8e2933ba968b00b8a30693753f9614122734b451400b48ff76865a56a0066df96961eeb48b9a10ed928026a5db452d002514b450014734ad476a003fdea72d250a0f34085a41f352d14c04a297f8452ad000b483ef52d0d4007fb34ea6d3a801b4e55a36fcb4500142fd69695a8012929d8a280128a5a314002a9a19a8a56eb4009fed514ea2800a6d3a8a0028a4ed4b400c6a643d0fd6a47a8e35f9050039bef0a76299ff2d2a5a006e28c52eda39a042d369d450014dff7a9d4daa0128fbb4fa6e280128dd4b8a2801b453b6fcb49400949ba9cd494009ba8e2979a306801368a1852d1400d6a2976d2d00369b4ee68fbbda801ad4714ea4db4005253b149400de2968a77f0d003698b4fa4db400ded46da730a476e2802273b9a8a45a55f98eea007aad2d2d23500252719a5a2801a7e5a19a86a3eed00250d4034b4009494ea46a004c51834b4941214da5e28dbf2d00373f3514fa66371a0a0fbcb49834e5cd25048945041a28021dbfc34547f68fef2352fda17f891ab33725a4e698b70be8d4a255a007352d279a9fdea378a0039a5a45756ef4b914002e68a329fdea3f1a040b453b228a6026da36d2d2af4a004c514ea31400d55a5db4bb76f7a5196a006ed14b4b4b412252aad3a8a0028a28a001734514628016968a314c067dd2691f0b86a715dac1a875dc8680255a5a8a07dc2a6db400b49b451f7bbd2d0023529feed14b8fe2a041452ad18a004e68ff6a9dda968018d4ab4bc50b400b451450014668fe1a28005a334ea42bf35001450b8db4edb4009452eda185002d22d1b696801ab4ea28a0028fe1a28a0028a314b4009452d14011c87e43491fdc14970c361a727dda00605fde9a997a54510f9daa5c55007349ba955685a0029bbbfd9a751400514526ea005a2936d2d00368a28a0039a40296855a003f868f5a28a006d1fc34bb68e16801293eed2d14084db4b45140051452714009453aa3fe2a005dd48cd4b4500252f34b8a6fdda005a4a5a4e2800a8653c85a9256dab5120fe33400ad4f4f9714d5cb3d3f6fcbd2800a46343514008d49ba8e68da2800e695568a56a006eda1a94fcd4da00293750d4500251cb5140ce2800a2865a314008b49fc5433514008d40349cd29236d0027345297a2802b6c346ca7efa371accd88f61a5d877548ad4abde81116d2a69769fe21526ea28023fc2978f4a78c52e45004781e946d0c2a45a38a04478146c0b52ae2823750047b452edf9a9fb697f0a008d976ff1352fcfeb4fc06cd1b05003065bf8a86cff007aa4d8286028019f363efd01a4f55a7eca3073400ddcfeab4a0c98eab4ec52ec3400cdef4ecb52eca361a004dcd9fe1a5dedc7146d342a9a601e6cbfc31d30cd37f0c3537cdb69ab9a0442f713ff000c153fdeed4734aadb9681902bcb1165f25997352adcb6eff52f4e77f2d853c668023171ff004cde9cb703d1a9cb9feed2f3f7b6d30104c3a61a9dbd2968fc2800de28f3128a5dbed4009e647eb4be60f5a36d2aad020de3d68debeb46d1bba518f6a042ef4a370fef51b46dfbb48a9bbb5002ee5dbd569770f5a4d9fecd1b05002ee1eb4ecad3020f4a76c1e9400b9147e349b051b2801db8668dd4cda3d28609e94087ee146e14c551e949e50feed0325c8a2a2f25297c95a0092866e299e5ad0618f75021f9a5dd4cf263f4a3c88e801f48485a69b789bb5235b43e94011dc30e17fbc6a5fe1a8becd02b8603e6a95bee1a02e361fef548b548589fbdf689ff00dddd4e16926ef96ea5a0342e5155fc993fe7e5e8d92eddbe7b5017458a2a054957fe5a538799ff003d280b92d25317ccf5a3f79eb4087f3ceda6e0d27ef1a976bffb3400ea1b349f37149b9bf876d002f38a5a6af99c7dda46f33fd9a007d3693f79ed4dfde7def96801ff00ed518a63193fd9a37c9e8b5403e8e2981dbd1693cc7f4a007d235377bfa526f66ed400f5cd2734ddedfdca5695bfb9400ab4b4c691bfb951b4f27fcf3a009b8a43f2d44b70cc7fd5b52f9c7f8928024fe1a6d46666fe18e93ed1273fb9a00968aaed712ffcf1ff00c7a98d7375bbe5817fefaa00964fde385a56f945450f9bb7738f99a9592e378f291197bee6a009d568a857ed7ff3ce2ffbea8df75ff3c93fefaa009a8c55569aed5be5817fefaa56b9b9dbf35bff00e3d401678a4aaa2e6e377cd6fb57fdea779b3edff53ff8f500586a4a8bcd971feae8deff00f3ce8024ff0066939fbb4ddcff00dca37b7f72801d8a4a4cb7a5196f4a005a29bf3d23799e9400efe2a4634dfde7a2d1ba4feed003e9b8a6ee939e28e6801cdf7685a69f31bfbb4624ff00668003ee28a42b2139345049153a9b9a5dd599d0046da55a28e2800a5a4a5634009fc34b451da81077a7d329680178a09dd4942d0217d169691979a5a600d9a5a28a0028028ff7a97140052f7a4a72b50014e5a4a2801695a9b4bfc3ba80055a2978a5a090fe1a2968a0016a3c6d7ff65aa5ff00769922f46a006cc3e50cbeb532d465770a7c7f705003ff001a5a6d2ad301569768a555a4dbf2d002d0aa2968a001a9690e296800a5db42d2ad0026da76da38a28106da565a28a00314628a5db4006da5a4db4ab4005263e634ea28019814ea5a280131450d450026da368a751400dd946c14ea2801bb68db4ea4a008197f7b4af9c519dd21a56a0072a0db4aa829d42d001b29bb06ea7d2d0047e58a3cb14fa280b0cd828f2c53e8e5a810d0949b053a8e2a806eca4db4fa4e6801bb68dbfed53e8a00615f9bad3761a7d1400cdbef46c34fa28023d94852a45a0e68023d949b29fba8e68018a94629d450047b3de9be5d4dc526da008bcba3cba928a008da3a4f2a9f450046c879a8b7fef0254e4ed06a18976e5bf89a801e4055a39a29db76d00379a39e69ff00c3450033068d94fa4dd400cd942a53f750c28019460d3d6931400c55f7a194d3e9ad8a006edff6a9db28a750037695a6b2d39b349b4500262929f8a6500149834ef5a38cf5a00636714739a7514008017ef450abc51401569d4da75666c2375a5fe2a31450014519a38dd4082979a28a004fbd4efbb49f8d2e28015696936fbd2d00229a5a28a0414bba8a280168a31462800a55a5a16800a2976fcc285a602b353a9b4bb68005a3bd2d1fc340053b34da7500148df32d2e2976d0491ad3a3feed26df9a85fbe28026c0a30293bd3e800a5a4a2980b4ab48b4b40053a917eb4b4005148a2956801696928ddef4085a31494ee281877a5a45a5a0422d2d145002d1494b5401451430a9012968a5cd00252d251ba800a28dd4b40098f9a929d4da008b60de697f8c52d18dc68024028029bb76d3e800a4a5fbb4500250d4b42d0025253a8a006d18a77f0d235002714350b471408291a978a2801b452eda5aa01b451450025253a8a006352d2d2500369d4514008d4b4536801291a9d48c280129b8a7e03534b6d14011bfcc42d1f75685fef51b680142eda77dea28a0046a45a737dda4db400949cd3b1fc546da004a36f4a5a375002514b48cb400d6a29d49b6801bb68a76da368a006b5252ff00b5477a005a6365a9d46da00652734e6147dda0045a4e69dc527f150034ab77a29c31939e68a2c05288ee5a77de6a897f76ff00ecb54ad589d02d145228a091697bd0d455009f7452d2ae29280b0352d3a9b4007ad3a9bfc54bb775020ef4b8142af146066810b42d14bf768001f2d2f34ddb4fa0045eb4b452ff00b54c05cd1eb494e51400b45146df9a801cb452014b8a005dd4b45273400b4668a2801a7e5348d4e71f2d237ccb4012714ea6ae36d3a82429cbf769b4ab400b450d4734c0751451400734b4942d002d1cd1cd2d0014bff02a4a5ed400b4514500145142d001fed6685a285a0017a52d1403400bfc34518dd4c661f773400b8a372ad44c4b50bff016a00981a32299120cfcc2a16ccb21dbf773c50059a6b1a97ed722f92ac55962e9b941a4b8712333305dcdd36f028110d3d5698b5227dda0046fbc295982d27de6a928023f9e979fe22b4eddb698c76b5003f6d27ddc53a8a006d14ea2810da4a5a46a00291969dfc549ba80128e69692800a286a4ff006a80169b4ea16800a66da7d23668012936d2d25002352353a8ff00668012916968a0028a29b400544ff3305a958f5a854756a005a5a07cc69d5403697b52f1462800a4e2978db450037f8a936d3b6d273b680100a4a5e5a971400da5a28e2800a4a5e291a800a6353b6d26280136d1b69db6928013bd2352b1a4ddb56800a637cc7e5a7b669ad400949c7dda7518f97ad00355793452ad1401431b969d09f976b50ff2fcd4dfbadbab13a09a8a456dc3e5a5fe2aa24377cd4b9349cd1400ab4351ba8a5601569d4da56a620e6968a28005a3d28c51400bde9f4cdd4abf5a0075148b4b40828a296800a72d2734bda8015697752628a005e696929cb9a60253b9a6d2f3400b4ea4a5a001aa35a9299cee34122c7525469f2bd4b40052d252f340053a8a29809b695a8a07cd40052d14b40052eda5a6ad003a8a28a0028a2939a005a28a467da3e6a005a2a232ff000d4335cc512fcc559bd2802d03baa296e445deb325bf323ed486e24fd0523de46b8f3acae3fe04e00fa0a00bc6fe4dbb9a17d9ff004cd726a2fed58d0fcb6578dfeea0cff3ace3e25b449445346f02fa6d2dff00a0e6ac2ebba4dcff00cb7ddfeed022e7f6ac7bbe782ea3ff0069d3fc334b0dfc13fcd148adbbb55486e6d273b6def564ddfc0cdcd4ef6658965daccbd9a802dab85279db51071c321fbb55fed251cb4a8cdc6ddb4fb5546cba9a00b321e9b69d2b08adf7b3fcf9fbbb6a27942b325365995f1bb6eda007a4de60f951956a5e180e6a934858ed51b7fdaa943fca158fdea00b83e51fc55280597e5466aadf688f6edced6a7b4f1eefe2a007c914eaa3746cab9a85f3b8538cc3fdaa634d1c8c68025dc569dc30f96a3e3f869accc8db968026a2911c3ad3b71a004a28a28103522d37ef3eda7b500368a5db450022d1cd3a91a80128a5ddba928011a91a9d4500371494fa28019452e692a8036d252d14008d51f3525359aa408dfb2d253bfdaa70154022ad3bf8a8a33400da29d8a31400cdb46ea76da4a003f8a8a1a8c8a004634d6a7d376f5a004dd49fc34ed949b6801bb6969cd4de16800fbb435149f79a801298dd6a5a66dff6a801ad8a4a7eda466db4006dddde93bd2b501b75002353335253596801b91451b7d68a00ab4cff0065a9fb7e6a1977562740c89b692b52d42cbbaa489b72d500ecd14519a090a5a28a0029691a8dd40856a75368a005dd4bfc54514085a3bd266968017f8a804f2b453a8005a3346df968fbd4c072d1494ab40052eea5a280169692971400ea291a9d4006ea45f99a97ef51b76d002d35a9d437dda006ad4b516ddcb5227dd1400ea2929680156968a298052d252af6a4026697f1a28a6487dda7d368a0075149ba96800a28660b8ddb7e7ce2a2b89160432b1f96801d3482240cc7e6ecbfdeaa724e57e694aeefeeaff0d236e5ff0048b8fddeee07fb23d2a94b730c4a2eae3e54cee44eed401784db943e36a7f7a4a65d5e5959c45e59159dbb2ae4b5635e6b704ecb14522b3a9f9fd22ffebd416cd2b24b2b23488c773bb301f9e6a80b136afe64acde5cad17fb2a7f2acdbef11d9449b2e11fd97a84a8355d56cf6ecbb9d95146df26db2031fa9c5715a95dc4e59a28fc98376df6cfa0cf534ac51bf75e29d39a52897be5b6793e435634de25d3a2937a488cdd9e2cfea0d73177a9067648836caca94ee255772b355580f4087c6f6f14bb99d95fb989f6eefc0822ba1b1f8876b2389567457efb57cbdff54e99af1467107df0dff01ab29232c492c532b2b02df7beefb1a2c2b1f45c3ac2df224d6b26e65f983c75634abb46926dc7e66af00f0f78bef343b80f0c8db7ba6eaed6cfc7713c31cd0c8b1de33063bba27a934ac2b1e99a95e451e1a2917727566e1101f534d6bcb68225769124e9fbc66c7e22bcae6f1c4501646925b96ddbbfde3eb54d7c7d74ce658a05f7f31bf4a02c7ab8d4a3b999a5877b2f63b31bbe956adda791fe50fd3ef579c278eeea0956268e26da0339f72338e6b7ac3c706740ae912a77ff0067f2a02c762e0400f9a8cccdfc5bb3fcaa35bfddfb95ba976ff75aaa5a5cdc4b08992158e261b848adcfe950c886e5fcd5bbdaac7ef3d005c966dbf76efe46e8cd5321bb588379d132b7f1560dc05b398fda36c8adfc4ad9aa6d7e2298aa472aaffb2c4500768b713c4bfbd8555aa44bd8dbfd6a32d72567e2ab8b353e6c32cd1374f31727f022b5ecfc43a7dda868a4585dbf819bef7b60d0236bf76cbb90d3f2cadd7756745776ecdf2bac2cdfed652adc736d6114bf7bf46fa1a0458563e94fa8b7d3d9a80111777cd4edb4b4d6a0075368a168011a8a5a7500336d1b69f4c6a0028db4514008d49b6968c500371494fa6f14009b6968a46a005a89ff00bb4f6a8fef7cd40053bb7cb422eea7eda004a29692800a6d3a93750036929d8a192801b453b14940098a29370a18d002d31be56a7d26df9a801ad4de334fc0a4e280128a1a8a0029b453a8023e3d693ef53d80a4db4009452d26edcb400b49b7e5a19a80770a004e7145295e68a00a3b7e6a29396a3f1ac4e806069bf75b7669f9a611b68025cd2f15046e54ed6a9aa8055fad1b69bb69d40094ea4a5e78a090e69d4de7753b3408285a28a005a168a55a0055a55c536956801dde85a4a5a0414aab42d14c0169dcd145002ad2d22b75a7d001450b4b40052d0cb47fb34002d0cbb969d450046b4f8a9a73934b1fde14124d49b69568a0a0c51814b42d0026dff6a8e5697b53945003573fdda1b3fdda7350b4c04c9f4a751450482d4998547cc8cdff0002a8e86fad0051d45a56ba4b8b7855bece376d66e1bdab2ee7c496f7d2b4bb1e24b723f74bcef93d3f0aa3e21f15369ef7112fddf259633db39c1af378b50bb9dffb41c32c4a1b03de9a451de6ade37b49e46d88ff006856d91acadfbb41f87535817fe2069cb3a4cf23fddf40b5cc5abfda5a49a793c8b751f3ee5cbb01fc2be84d4123c9a9b2dac28f15bae5b6aafdefa9a7603a3b3ba91506c816754fe16970327b9c5598f5e163707ca76bb7efb57f7687d1720d6779326996d6d15bc6d2cf708ac440be6150dd01c7735d13e986d6009741d6e147c865e027a8c1a616395d5ef2eee5c4b33dac6edfdd6324b8f7ec958779751ab2b5c4f3cdb41c44adb51735bda8daabccd0c2cb23fde2514d73f7b682d30d2bedff007793f4a60635c5ccad9484796bfdd56cd66b2dc67733b2b377ad89409db6246ede8aabb6a6b4d2a196567b87db027cceb1ff0017fb20fad5018f6f0ced0c9338fdd20ebd4bd4292f96ff00295556fe1ae935d69b6a594489e6f0f279780910ecbf80eb5cedf793148555376deadda81908b9da64ddfc5425c967ebf2d432c262c4ae36ab13b3fdac5104912b7cc5968035e396491b6a7cccddeb66c0dbaecf361797cae9b780c6b1e390342ce8ebb9718edb87b7b8a745a932b1fde2ad481d4a299c1668d23dcc5822ae028f439ea6b7b45758e55dd3ed563b7ee8c5717657a1bf8dff00efac56fe9ba888153eecccdf36dda5b8fa2d211e8f60b6572cab6f1ee971b4bec6f96ba24b5b48220f2dabcc8abf7d10fcb5e7361e2383cc05a46dfd919a403f000d74675d8d62dfe469334512fceede648133dc838a40666ab7767248cacf2c7b4fde7c0ace8b50b7b6df3433798ea0e03ca406fcaa8f887c536f3a146165d7efc11795bbf002b8bb8d56167f95e803abbbf114f1ca5dd2065cff00cbb367753acfc6712b15960dd16776c6f5ae2a4bf5dbf29f96916ffe61b76eef5a00f54d37c4966ee3f793db2b7467e42fb122babb7bff00300fb92a29fe0707f2af0d8755315b1d934b1b37cb27c998f1f5ad0d1fc553d9b6df3b744dfdd6e29589b1ef105facb8557fbbd9ab42271200cd5e75e1ef1279be53b1f393fd9eaa2bb8b798300d0bee46eddd69899a549b6a28a6dff2ff00154d4084db42af142b1a39a005a28a28011a9156976d2ff0d0036936d3e9b4009c514b4dc5000d48c29685a004db4d614fa6bd0046f48a0d28f98d382ff150039576ad0d8a292800a4fbd4b463e6a004a4dbf3539a93d2800a6f1450b4005252d18a0066da36d3e98c6801714514de6801770a46a4e69f40116da455a97b536801bb697f876d19a4ddb68017eed35a8e59a9d401173f7685534f5a1bfdaa00630a72d149400a4734534b51401468a36d0b589d02d0c3e52d4ea45534011b7cc2a447f3169a576d31b313eefe1ef4013d140edb68fe235402e6929714628245dd4376a4a750014514aa05020a556a4ef45003e8c522d1ba801db6978dd4945003e85a2939a042d28149473401251c5369dfc340053a85a16801d49b775252f3400edb46050b4b4c063aedc5357a86a7bafcb4ca009969d51a37029f400b452ad3a8013b51ba96936d002f345145300a5e2928a005c9aa1abc92343e4c2db6597a1eca3b9ab37370b6d1b4aff753ad705e28f1caac6d6f6b3a46d296432b7f08c60d006078b648276816d3cd6fbbbfd1573dcfa9acabcfdfcc2d2d0b7956ebba5dadc20e8054b73a869d67e1832bcfe65edf309a348d78b7553c293ea6b919b55bc6b3316f6582590ca7b6e6f5cf7c56805ed53510d706242b1a27cbb57a558d37508d5915a7f953f83caddbfd8e08ae712331209650cbbcf1f4ab36379f6673bd11b77ca3fd9a067a4693af2da45f25f34aec0ec893e508b562e355b3c6d5d29a77fbc59a56e9eb915c6e94fc1b5fb3337da06ef9588ab8fa8ae9e9e4c50452cee36ed65cd0069cfac58c48cef7104098da228b25dcfd057237faadd5dcdbe13b57ee85e37ae2ac4bfda5039f3832bca37385ac776b859044b1a468c7fd6371401a11dce9f676a6e35379ef6fd9bf7769136063d58d625f6ab7b7331958ed6c854862ff00569ec055a9ed218a564864f315be67976e379aa6b73a7e9d2ef9a38a6661c2b649fc85032cea3e469f6aba7c375f69ba65df7f3aff00cf43c8894f70bdfdeb9a95e691d62877c8ec7ee2ae6ad5fdfee7548a048d986d0abd71545af27b6866b589de2f37e5936f571e99f4a0092694ee0b2bab3a8dbf2f44f6a4f35625f947cffdea21b03259b5c79f12aa384756e3823ad4583bf6a05db40172295593e7f9994f1576d62859be693f055acd8d377cabf355d82ed6350b9a0474da73c7137c96eb2b77dcb5dbe8ce1a32ab6fe62ca3e71babcda1bc0c819b7afe95afa5de49e66e89d36ae171b8d0163d52df4f86540cb63a4c32ff00195c33b1f7e2a86bfa269cd6437a5c48f819f2972991ed58763e238ad98adc5da2f1b8f96c03d74b6be39b3962f214c5e52f795e908f28d5b4b689cbed68d7b6ec8ae76e6da48f2cbbabde2fa2d2752d3c4b6f059c7b871e432835e5faed9dac136d86168d7d59f3401c62dc4b177a9a3bddf8dff36dab973089146f8f72fad526b35c968a4dbfecd30342daf644f9d1d978e195aa4371b9cb31fbd5951a4892ec6f956ae46565fe3dbb41f99a9058dcd175a9f4d984b14d5ea7e13f1a8bcf2adeeb6abe7e49b770decd5e20927cfb93f86ba3f0eeb06cee57748d1a4a7616ecb9f5a407d16926f11951f786e46ecd56e17f357fbacbd6bcf7c37e24934e9ffb3ef4afd9e5f9902f28adea2bba89fa3a1dcad4105da5a6af4a5a005a4a296801334352e0d250019145145020c5369d9a6d0022d1ba968a006d31ea46a87ef12d40028a969a8bf353e801bb6978a29b400bb45251450014dc53a85a0066da5c5148d9a005c8a6d142d00250d4aabcd1400dc51c6da1a918d001b7e5a5a6d2738a007d329dfecd1de80198a0818a9298d40083e5a1585368fbd8a007526d34e0bb6931400d65348542d3cf7a858f9a68010b6fa29dcd14019fbdbf8a90c927f0a549c51c73589d046d2baff051e749fdca93606ed46ca008fce91bfe59d3c6645f9853f68f4a6b7fb34011abb444a6cdcb4f69ff0085a37a47ced2cbf7a9f0e2501a801a271fdc6a7accbe8d4ed9fc549b02d0487982944a1a854146cfeed5006e1b697238dd46ca568e8106453b3ef4df28f14ed9400aac3d6955a9bb3a52eca007034b4d58e97cb34087e68ceea6eca361a00917eed3aa2da69550d004942d47b1a97068025a754386a72ab500498a5a8f9a3e7a009569d506d7fef51b5bfbcd4012d31699b24ddf7da9c8bb7ef1a603a36f98ad4ab559e33b832c9b69409ffe7a7fe3b4016b6d0a2abee976fdfa7664fef2d004f8a3f8aa2ded4ede6801f8a314dde69779c530168c0e377cdfecd3a185ae5f6e5635fbceedc041ea6b9af1c78d2d3c2f6922c50b4cd32ed88b71bb3d1be940ac727f153e205d6f1a3d922da5bc586253fe5ac95e77a55c45aaeab026a055a28be723fbe146ec1faf7359baceaa6faee4657dccfd775476d24362859a4dd7128da76f4894f55f727bd522ac6d5e6751691a2f99781b157ef31ac6d666692fe58b7fcb17ee917fbbb78c56c59cd7306912b411b33bfef7e5eaa3b1f6ae5d124966919df72afcc76f3b73ea69dc64667932503fcb5a9a75e32bedfb2acbc6dc76fc735857173bf2a836ad224be6eddcecb12d1703bb8f5e5b484433c090acbfc0ac4ee1f853a00b724ff66c3b6563bfe66f9221fde6249c57222e61dbb62dd22ff7e56e7f0f415a561abac4043146b3331e62da48cfd17a9a77037ee34f9e48a495ee9e55fbbfbb5c239f626b9db8dcd26c4755fefbb30c71df35d45c99b4fd3c5dead3f97b81f2ed15b9418fe3fee0f6eb5c0eada9c9abcbb507ee93fbab845a2e03a79d249cac53ee8941fbabc30f524d51e7124bb36b60796cdcf07bd5f86daded117ed1fbc5eaff00edfa2fd29d9965647c2abef2d1a2afdcec28b95631a5866b6728c1bcdef4e8218e57ff00482dbbfbabfc557fec72365b0db72545588f4931b23799f337cc432fdda5743e5656bbb6b87b75473fba41fbb8d7a2fafe3513d84b128697632e38dad5d3d9e94671d1e45c8e3dfd6a69f4c8226911e156563fc39f968e641c8ce4090b8f29fcb65abbb63d4222ee9b6741fbddad8f347f797b6e1dc55bbcd0ce9fb99c7de5dc9e8c2b3de091be6028e641cac6456d2a80d6a7cff5f2fafe469c2f1205d97bbb6ff71783559a33f74fe34e46b8894324eca99e9ba8ba0e52e2eb7a6b2795e4de4516776e8d811c7aaf19a921f10b419fb3cf673ae3ee4f6f8dc3f3acc7d467661ba3b591b3f79ade3f98fbe00a7457f27da5774164a9f7bfe3d569a26c6a43e2dbe8252c82d61ddf3620887ff5ea293c572b616ea0f355baf60dee3155ef6732d9c333dae9b1b79cf13b416eb195e32385a9ec3465d6b4eb8587ecad2c4a1f779a239139c639e0d508abfda8ad217b7df1ee1d377f3a433095baed6ac89229ad9f6386565fef54f0cfbb1ceda0469acecbf2ca15971fc552dabfd9ae2197f851b77ccbf7aa823865dadf9d5ab77e7631a902d4c23b6bc9e2859b66f3b3e94b0cd244e1b3deab3cc1dc95ab56d04928ff007982d00775e15be92e40b7dfb955786ee86bd47c27adfda7fd12e9563b887e52bfdef423d8d786f87aee5b5bb5442dbd4ff0fb57a1d86b0750b882e3ce559d3e52ebfc429325a3d6d250d8651b6a5aa5a5dcadd5a2cdf2fcc0355dc8a448628e697228dd4084c514b9149bc6ea001a8a3228dc3d6800a290ca8bf2e6986e22fefad004949b6a36bb8557fd62d46f7f6ffc5325003a63b7e55fbcd489d36d46258e425f7aeda513c3bbe691680271f28a314d59e16fe35a779a9fdfa005a36d37cd56eeb46f5fef5002d149bd7fbd49c7ad0025253b8f5a38dd400949f7a972b464500251485fe53470dde8011bad2734ee38e6938a003149b68c8a375001b692866a4c7a9a005a6d0d8f5a322800a7537775e68deb4005250cf1ff007d69be6c5ff3d16801d48d9a4f3e2ff9e8950bcc24f9222adef4004b297f914fcb4f036e16988ab1637155a91648957efad00385148258cff1ad1401438a5a4ef46dac0e805a5fe1a314500145149f7680108da6a34cc536e5fbad53f0d5114eaad4c09f777a158e6a3b76fe163f354b4122d1da932334bba8016954d26df9a9769aa01d4b4da5dd4085a7605145003b342d35696801f49c52d277a043b6d0b4b450014ea6d18a0055a5a2956800a5a314bda80168c5145300e3753251525232d00412e5454eadc5458f94d4910e28024da285514bfc54ec500204a5c0a29cab400d54153c166d2a6f5fbb90a3fda27b0a4b6844f3c68ceb1ab1e5dbf8455ab9bc874fb77bb64f91415b78dbfcf5340195e28bff00ec1b28228a349eeae4edb7b65e4bfabbfa0f4af9b7c5be20bad6b529aeaee77939dbf95765f10fc592cf3dc5a29efccdee3b0af2ebfb98e54d96fb999bfd63ff00773d855948ab2dced76dbf3331e2a458a25782dd64dd2b7ccedd94d54694464aafcdb454f60e3ce32b8ddb7ff1da00d7d6bc41e6e976b628157647e548578de03330cd62453182da746dcb2bfcc9b7d7dea3bbb8f36e0f3b571504d26e7dbfdda0a1a5b6e38f99a937f1b57f8aa3797e6dabb6951f7765a605fd3ec24bc902ef48625eb2b7016ba6d3f5eb4d0c343a65979d2b0d86665f9dbf1ec2b958a53fc459aba5d2e286d6d9e6be2b0c4abcc5fc729ec00a00af790cb78ecd35c35eb676f970711a1f427bd57dd6f66a59ca4cea3e4863fb8a7d7dea4bed5a4bcf33ecf1b470361620ad80b54228995c27cbbb3498d225b74329f35c2ff5e6b5f4db04e21f9bcf95b8ff00641aada75b169b6ff77ad747a6c416ed5986e55aca533a214f42fe8be0a92fa6ba852783cd893747148a7f7bf43daa95fe8335adcaab855661f5db5e8be03dde75c5c246ad2a0f919fa20acfb9d2a2b6bbfb44a1a75676ceee3756529b348c15cc4d174e896d9a2f9bdbfdaa9eef4b8fc868bcbfba7766b7746d2bcf95e18a3791946e455abd73a686b45750acf8ddb56b27366bc88f38bed3d9e2f2986e5edfecd73b77a6ecfba95e9f7fa618d0a38dad8ae56eec59b72e376da4aab1fb34719259d5392d5bd2ba7b9b431fde154e680f2b5aaaa43a48e59edf6cb44530f23ec8c36bb481e37feefb7e35a9736c377cbf7b3cd65dcc3b1f6ad74427739a70b152ee6e043b15576f3b78dc416e7eb52c76d22d9dd4b115548a346917be18a8a86f262d1ac2c8bf231607bf35089a446db96dcc361ff687a56a60c4f34eef9cfcad5398846c3ca74957d56aacb8dc38a2272a6802eb767f6e6ae5a4a770753fecfcdef493451ad940dbd59a55673fecfa532cd0c98565f9b8a092c410c92cc2dd1373b90a83bb67a55cb34f2eebc999fc9f2a6db26de769a861865fb485dbfbd5ff00c771cd68693015b5bd6b88d592e0a2236ec14656dd408b16b15c41ac05ff0096ab216dcbd1b1ce6b5b44be363aa4af9db137ccfb79dc3350de40274b96fb57ceb18f2f72fdf2bb78f6359d6176609559be65efba811f42f861f72b44922c913a2cc857f8b3d6ba444f96b84f87f2182c6da173b966532dbb2ff10ee0d77e9f28db52431bb28d952514088f651b05494628023f2e9be57f7aa6a28020308db49e42ff00756ac5368020fb3c7fdc5a63c3171fbb5ab0d51fde6a008fc98b6fdc5a16da3ff9e6b52e3e6a7d00402d957f8568f207fb353734b4010f923d293cb152d3a8020f287f08a3cb153d32802268e8f2ea5a28022f2e9be5d4f46ddd401094a4f2ea66c6ea6d0047e5fcb4d68ea6cd250043e4d26c1b7a54fb693028021f2e868ea6a6e4d0042c94795baa5a28021f2a93cb153fe348d8a0083c85fee527d9a3ff009e6b562a377dabba802acd0c71fcab1ab3353e18846bd3e6ef4f453f7dbef54bb7e6e9400c68fccfbc8b4d36d17fcf35ab1450055fb345fdc5a2a62b450067d373b56947cbde8e18f4ac0e8168c9a4e296800a5c7f7a93fdaa5a003fdaa43f3528341fbd4c08dbe560f538f9be6cd42cb423ed6ff65a8249a85a3d2956a805a728f9a9b4ea005f5a2939a33408752f34d5a7d002734e5a4e3d28fbac6801eb4b49ba9734007f0d2d14b4083ef53a936d1cd003a8a4a5ff007a98052d3a8a00296929680168a16977500458a74343d353ef5004f4b483eed396800514f5a45a5a004d85dd513ef31fc16b2fc43aab2457d35bbf98b6306d476e769fef62b6adb4f9752495a2755f2b18666ee4f5fa0ae47c657c348f05ea9343b639f22dd372f77e4f1dce16804780eb77e2e6ee577ddf31dc7fd9cd615ccc25fba15557385ab7a9cd25e5dcb2cadf331dc7f1aa1b82a1dc1b6af4dbeb56684326769a50e56208a3ef1a8dd4eff9bf84f352cbb7f77b67dcca390abf7680237cab6ec2eeef55666daa59aad4df2f7ddfc554ae5b7628022197c2ff000e6a6e232284411814eda172cd4017609cc43754bff090cf16e48a18be71f3bedcbb7e359a65eec5bd956a29a4dc36aeddbde802fdb5f34b36e9666936fe59ad0b24124a19856359a0575ddf7bef56f6970fef0b7b544dd91d14a3766959a1535d5e9967b90ee936aa8dd585670891fa575167f29fc2b8dc8ee50d0eb7c1fa9b68f6d2b0fb447e7291b91bef513c526c85b6797fc5eb50e90ebf606460acd91fc35a6ede6f94cdfc2368f45a8720500d2b74522b279bf37cafb5b1b85684d00b4b93b76794ff00c2abc2e69f6cd1b2471449b9bfda6ef4d984afb918aed5fe1dd50d94919b7d60a8acbb3e561c573da8d9056dea2baa93cc961f9beea564dcfccc56a0b48e3efec971bd47deac3b9b6dbdabb0bbb7dac5587cb58b796d4d4ac16391bc876e5bfbb58d7ca132cb5d46a36fb37715cb5f81bdb6ff000d76d07738ebab18ef16e72cd555d76fcfef5a3fbc55eadd6963beb8b63bd2e1e2ff0075b1babad1c2ccff00bca3fbd8ab5058feec5d5c7cb076f594fa0a4fb66e3bf6798dfdf93a7e54f9266b97deedb9e992c9a7b869d0bb222f1f75780a070054fa53aaccacecd59d230de16adda6372ee3408d39261e7c8ecfb971b8edfe235d45968f0cf71142932790ee9bfb72d1e79c7a560496f0c09f30dbb06fdb56b4bd6e45ba876fdd460d9fef11da811db6a5a7594fa6a7d9e46f3ede42b2a37df6c57237f612d8b4a8e3e45646ddc7f10dca7f115b9a06a925ceac596448f6b87dbb72320e306aef8b34d927b1b86b48fccf2be6758ff8a307795c7a03c8f4a04745f0defe493474da774b6d38f97fe99915eb11e248d5bdabc43c0108b3d4a389675689b192bfc40d7b6dae3cadbfdc3b693209a8a2969084db494b45002518a5e292800a28ceea6d0031cf5a6d3bef351b68005e94ea36d2d00368c53a91a80128a1a8a006fdefbb4629d4500336d1814fa635001464d251400526da5a4dd40098a4a731a65002d251462800a4db4e0291a801acb49c2e2969bceea0028a361a33b7ef50035fe51baa355dcdba9ce77d3d102d0022a0a5e295a9bb7e6a005dd49914aabc50b8a00431e4e68a69c9e9450066b75a377cd494e5c560748b4668e3eed27ddfbd4087535be5347dea5a004ef4bfc54b45002fde1b6a265fe1a9698c2981246fb853aabe4a90df9d4fb837cdfdea09141a5a6d2a81400b9a7526dfeed2e775500b4b49c7f7a8a043e9698b4ec5003969d4c5a7ad0014b494a05002d3a994b400ea28a55a042ab52eea6d2e2801d4b4d5a5a0628cd2d1f8d140847fb94c1f7853e99f74d3027e56955a910f14fc6da007ad33990edfe1a5db470b401bda520834b95d4ed95dff0077fed1515e1ff163c47633e86d630ffc7c7dafcd77ddf7862bd63c633a695e16b4bb791d5620e488d797c8af963c5ba949a96ab2cdf2ecff0067a3508a8a30257dcc7716aad2b0da7736ddb4b2b8593fd9514d685a4b55b8caed6729b777391cd32c8e271b77ad2db46b2edddbb731dbeca288ece49d64752b1a27df766c05a3cc545daa8adefce6a865ad663b46bcdb64ebe52205327676ee4561b7cd2aad684adb94ed3f2d54daad36ec6d56fe1a009562dbf77e5a8259072b53cec152aa203f7bde801bf798b628886f755f7a9b66df9734f8a22cbb947cd40d227846d946d1baba7d26dc6c1f5ac0b7b4f3376eddb715d5e8509f28573d69687661e3adcd2b2b73e72edae9e083701bab2ec23f9cb2afdd15bd6d10d82b89b3b522f58c7e5aed5ad3442ab59b1248a432b355f81a5fbad5370b172da5ab9bc7f02d52870a6ad43730c59f36369290ac4770ff003155fe2acfb80197a7cd57e66694138aa8c9ed52332ae61592b2ee6d07ddc56ecc9542e621b7750338ed560f94b62b81befddb337bd7a5eaf11d8cb5e73ab32a249fc4ead5d7867a9cb89d8c673bbe5a8766f7db9f969b2b94a6c6f5de8f3d965628f77cdb557fd95a7dc446cd86efbcd86db502dc18d7729a85a666fe366a77209f6afdff00baad52db2191c33fdd5f9aabacbfc46a492e4f0aa28158bb717926a7a96c4db1abe102f6e2afc56cb0619a6ddfc5bbb2e0e0922b9c8a568a68e54fbca430ad9864fb5a3339556dace59a988d5f0deaab67af45bf6b412bf94e76fa9e18577ba26aab1bcc654591629ca18d9f1c36eefd8fbd794b27fcb55fe13cd6d693a84bf71a4f95fe43bbf873412d1e81616f0d8ea91dc5a46df67f3cc4f26ddbcf5008ecd835ed9a7379916efef5783695afb3456f69708b26dc23ccbd650a7e527dd7d6bdbbc377a2ef49b775fe11b4fd69321a35968a28a420ddf35149b69714009f7a861451400546c4548d5135000abc5395685a750036929db451b6801bcd14ad4940052352d2500368e695852d00368a3f8a928006a466a5a4e2801bcd14ea2801ab4519a280118d273460d0ab4009cd1f7a968a0029ad4734734008c6a23f31db52335300a0055a72d3beea9a66edd400e3f3503148b4bcd0026edb9a8dfef0a969ac0677500318f3d68a54c64e68a00cbdb452668cd739d43fd696a3a55a0438fde34ea6f2b4b9a620c51cd19a28017751ba8db4636f6a006b8db44276b15a7544cb4c92ceda375351c494b40877f1514d1f2d2d031f45357eed3b9a0072b5396994beb5421dfed52ad315a9cbf7a801d4ea45a5a00750b4c534ea042d3a994fa0029d49464d003b6fcb4b4dc9cd193400fa5a45a5a007544dd69f4c71b7e6a0058bfbb53ab0aae8c7754f40127148f4ddd48f22afccc7eed00701f193c47347a7450a5c4aab3064088dd9460d782cf28542c4b36daf4ef8b52f97a89457dcac0381fdddc2bc9ee9cc8fd7ef53358ec40ff320fef31dd53c2d0adb4ab28665edb5bee9ec6a2e361fd2917e540985a658972c64c3617e8bd2a1e550ff007aa60bf216f6e955594e06ea0096370d094fe3cd448a19c52dbb6e7dcd492465652b5402dd6361dbeb50a7cc829f2fcd956a722ed5a00684dd8ab9145f28a8a25fef0ad0b388b66a1b34846e5cb0b6dc8abfde3fa574ba3c223057deb32c211b870bb56b734841231dbeb5c55247a14e3646ed9db6d8c56adbc3b80e6ab40bf2ad6843855ae7362d40a54d5ddd5561a9b3b545004e8d52a7deaaf11a957ad022794eeaa6e46d2b8f9aaf32798bb6aa4c9b5cad488a928dd552588b290b5a2eb54e51d5a819cdeaf69b55abcbfc496cc9773363e56f9857afea3116535e75e2cb03b0b36eadf0f2b48c6bc6f1380910c84eeddf3544176d693c1bbe65f9aa3fb1ee565c7cca2bd14cf31a2a2a0651baa7f2638d032fcdfecd33c92a956218bcc43b7ef53b8ac54969abdd7f8aac5c447cd1c546a83ef5324685f9eae47f3e36d5709b5fe5ab70feee32bef408b0c42a95cd2c2fe5f19aaeb29cf5ff0066a78c8cd3037b49b993cd8f69f951857d25e0d9a0b9d0609ad776c7f9886fe135f2fe9b36dc2b6df96bdd3e0feacaf637364eff0036edc8b4333923d2a85a45a5cd22056a4a4a5a042514fa635031ad4c55a0fcdf2d39579a042a8a5a2936d4806e18a46a314500142f7a293b5001499a2936d002e68a28a006e2936d3ea36a0056a4a28a004f5a36d2d1c500371450d4dda56801777fb349bbe5a3145001b770eb49b29734500270b4d2f4af51e37550053c0a70414bc2d003594b53766e35235276a006e0535a9cd9dc1a9aca71400e1f7a9b2d2ffb2d49bbe5a006851d8514b9345006477a5ff6a8a5ddb6b9cea05a55229370fe1a3018eea043b752d336d3b69a040bf352edeb49ba9dba9806eda714350d4bf76800ddf3535d772fcb4b834e036d00562c54ef5fbb5651bcc1b96a129f311fc3442de536c6fbadd28249d69d49b6939a621cd46ef9a9b4e5a005534b451400ecd3aa3a764d500bba9c0d3169e05002ad3d699c32d2eea043a9dba994b400edc69734da55c5003a9693268dd400eddda9dba98b4ea0050686f9968e28a008b353ab7155cfde352c2432eda0091b2dde908451b9a9734d75dca2803c17e2bcbbb5d756ddb5cee15e72f89262bfc59af5ff008cba3f957f0dd443e4952bc9e2015e456fbb8a66d1d8a7330595571f2ad589a2f32137113afc87695efcf43505e21561f769f1b8588aff00787de5a0a1be686712b856e791fdea836853f37dccd49c646e2b513fdda0761c1a15b82c91b2c4a38566c9cfb9a7cb6e67805d27f09daffecfa540c0b305fc6aec2de52b230f95fe5340ec66ed3c6e156214dd56a5b5f94aa8f954556858c527cd45c7ca4f6f6c58ff00b55ab6d0ed6dbedb4541a727cacedfc22b4ada22e0356552474d289a1630a2a6e6fe115bba643e5a2d675a4459c2d7456106d5e95c52773b22685b0381f2d5f857755785768ab908ddf3541459852a6d82a28fe56ab34008a2a45fbcb4c5a9928116a2c6d1b97b557b980ae1aadc2a596a4961dc9522324c678aab2dbd6abc63355e6b7dd9a0660de4276fcb5ca6bd61e6a6d6fe2aeee4b7dd9e2b1751b312b9dc3b534da7713d4f1cb9b0fb34ecac3e563c506155c32fddaeb75cd13692df36d6ac130989f67f0b7ca0edfbd5df0a975738a54ecec635dd93261947cac2a0b661048378f9735d959d81bb8b6327ddff00c785646aba21b494fdedbdab48cd18ca1d4ccd4ad87921946ee7ad65a461ab5a249d10ab8fdd6769aa4e9e5b1451f2d688c9a2b8fb9f2fad4eaa360151aa6d7e94e7aa246bbfcd56a3c70d8fbd5483066e956518f0b8a092e5b37ef457a1fc37d60e9be21b6dc7f74e7ca76fad79d40bfbd0d5d16833fd9ae15bfb87750268fa993eed3f68aced06ebed7a5dbb32fcfb067fdaf435a152603a93752d26da004a6b353db0b50bbeea003bd39453569f40051bbe6a28a001a9b4ea4e280194ad4a7bd36800cd1451400da4a7d35a80128a4a28015be55a673ba9569dc50046d4b4ea6b5500ea6b52351b6800dd4d5534fc8a1b14011e36d0c452b31c545f7a801c70d4f45a6815250027e348c29777cb48c6800ef470b48cd4da0092a091fe6a92866f6a008f3efda93fd9a91c2e0545f756801c1704d151860e3fbd45006479727ad2f9527ad4b9a335ce750cf2dfd6858dbd6a4dd450033648bde8db2ff7a9eb4f56e28111625f5a3649eb52e68e281116c97fbd4a124f5a928a008ca49bb6e68d926deb53677514010f9527f7e874debf354bba91c7f150490a79adf2ac952289bd69bf75c3ad58a008b74b4a1e5a939a5a60337c946f92a55a1be94c431656f4a5f30fa54942d0033cc3b7a52f9c7d2a55c52e050047e616ed4ab2fb548a053b8f4a008bcef6a779829fb47a52e050037cd1409853f65181e95402798b4798b4aa83d2976a7f768019f685a3ed63d2a458d5bb52f96be940117dad7fbad47dba3f46a97cb5a5f2d7d2802b8ba46976a86a04a237a99d028dd8a67dea00916e569fe62522c2314be4d00733e3cd1e0d5f48b866ddba1819815ebc57ce5770988b2fddaface5b65922646fe21b6be7cf8a7a245a2f892e22b7ff008f770b2c7b7f8723a5334a6fa1c05c9f3176d270b0855fbd8e69fe4866fc289b0b1f4fbd41aa4352e268995e22abe9f2834ebcb996e640f2edddfdeda07f2a8f66d51f4ab50dbf9b2c6cfb762f6a4d9a28dc8a1b491a31fde6ad4d3ace296e045286f2b1c95eb9ab16d6124a7a36dff779fa0ad5b6b116c8768f9ab9e55523a2344a50e97bf0bb7e551cfd6b235db0fb35d86c7caf5db4168cb17cc3ef7cd59baad80bb5daff0076a154772dd35639eb384b451aa7de6eb5d1db5b8dbb547cb54b4ed3bcbedf327ca1aba1d3ad8363fbab44ddc22ac4fa75b05c71f356edbdb9da36d32ce08d40da2b4edd02d60cdd6c49047f26d6156d22a6478c55942156a4a1152a5e169bb852b36e6a007254c8a2a15a911be6a046a5b2d4af851505bc8156a43306a902acc9f31aaef8c54d7120aa6f2eea00638aa93c0196ac994531da8030af34b4707e4dd5cede68aab274f96bb67db59f7912caa55aae0448e461b096ce6fdd49b97b06abb269b1df47f32355a78ce4aecf9bbd4b16539cb7bd6b7662d1cc4be1b48dfe5f978e4573bad68062dcf0a7ddeab5e8d3e246e954aeac23ba53fde61571ab24c874d48f2364dc4aff00129fbb48c0b2d749af68525a5c34bb36ad624d6d2676ff0012f5aec8c9495d1c92838bb14181dc1aacc23ab352321ddb714f50c985ab33689613b5d7fda35d3f866d8dcea30c58dca4d7388c367c81baf3f8d7a2fc2ab0177aceefe286332a0fc54504b3db3c3f0c9169b6eae3e784188fd14d6c7155ade291054b893d6a4c0968a89924f5a6b799fdfa0448f51526d66ef48d1b7ad0048ab4ea8d7ccf5a36c9fdea0091a9b49892970d4009460e6970568c1a06251b68c1a30568108cb4d6a939a6e0d0033068db4eda69b86a003eed253b068c1cd003194e28da69f8348c280128a3069369a004f5a6f2d4ef9e987ccfe1db400b8a502a36f3bfd9aaeed76df2a94a0096694b1d89447e6376db4bb0aa7ca3735025917fe59d0048d9a4e68f39bfe79d1e69fee55002ad39698d29dbf7293cd3fdc6a00919698d49e68da786a377cb4009f7686cd34cab8e9434a32386a00575dcb4301e948d21a6ac9cfcd400d3c514e2eb450065514dfbd8a5ef5ca760fa45fad2d2715448e56e945329cb408751cd253b77cd4002e2957149c525003a93b5252ad0205a7a7fb54da19a980d7c53a123eed1c3546df2b50496693eefcd4d46dcb42af34c07834b9dd4dcd2ad003d49a5ddba9bf7714aad400ea766a3ddf2d395a810e57a7ad32941aa01ead4b4945003b77fb34520f9a96801569d4949ba801c3e5a76ea65281400fa5a6eda4a0079fbb502d4d5111b5b75004e87814ea8a1feeeea916801d5e47f1b2ce15bcb2d83f7b2abb48d5eb78af36f8c7a7896c61ba63f36768a0a86e7863c5b64f9aa19f0acaac6ad4df34bb5876aa372c725b1f36283a10b1fef640abeb5d7f87bc2c6f143ca3e5cd62f86f4b379790aff0079abd82dac62b4cfc9f2b015c38caee1eec4f470d45497348c76d122b68c2a8f9956b2da12d348f9dbcfddaebee615da6b9cd5a58e00150ab32b72dede95c9424e4ce8aa92457bbbc8d15510afcb5977376248db95dedd05569a6dccccdb95325405fe2acb9a52bf2c5f7bbffb3f5aee8d3392533a2b330ec0edf797e515ad60e17eeaad70297f2464ab3aecabe9e2631a045156e9b33f687a54130c7ccd5704bb57766bcc21f16b2fde7daaa79ad5b6f19aaed668f72ffb4d594a8c8d55789e850cdbaa747ae22dbc696f277f997f86b56d7c4b6f2afca5bdd2b374e4ba1a2a917b33a55719eb4b5971df2c89bd0ee5ed5a3e7051baa0b2c2b53b7d408db86ea90668196e3b8f9687bbfe1aaadf76855a043de43254548ee235acebdd51626db9a12b8175e50b514b74146e63b6b96bff0014c7065b2df2d739a8f8ae6653b5f6ad6b1a326652aaa277577acdbc79daff003562ddf892250776c6ff0075abceef35b9a7fbaeedef59d2cd337765ade341239655e4cef9fc4f033fcbf7aa16f10897eebf96d5c2b4570abbbe6f969f1cb329fb8d57ece247b491ddc3ae9ddb1fef56dd9dcc72b46cbf8d79cdb5cb6cdadf2ad6fe9b7ed16d46ff0054e7ef2f250d67382b685426fa9d9dfe931df461947cd8e9d9ab93d6bc1fe46668beee395feed75fa2df097f74efb5ab52fad2396dca615b75727b5941e86fcaa4b53c1f54b616b398b66df46a80bee895ebb0f17e8814bbaa7dd35c8c29b5645af468d4538dce3ab0e564d6bfbc4f94d7affc11b10da94f37fcf28ebc934f1e620af73f82f6c6282f2568f6ef03e6ad4e69ec7a8d19a45a5a0c6c1934c7c53b7544ed4008b4f5a45534fdbf2d003695697145003a8a6d264d002d26ea18514006ea29334501606a4ddb6928ff007a80b033519a29b4087514dcd14058463d69b4eda293fdaa02c250d499f7a281d828a28e16802377a6a29a5dbb9aa51f28aa10a129db45337d0ad40c7361699c7a52eca4db4007148c05146fe2800d82930169777cb4d6a004655cf4a69dbba9ecb4d62280130ac3a6da6b45fecd39e4149bbe5eb400dd8168a5ce7814500622b0a5a8f76ea375729d649ba8a4a1681343a9dbbe5a6a9146e1ba810fe1a929bbbe6a5ef5402ff152b522b52e452b8876e14bfc5ba99ba8ff00769887d0ab452e45001de87c30dd4bbc522d00311f6b54dfc551baedf9a950f1b6801f47349b68fbb4c05dc569cadba928e68b9249c514c56a55a007e6954d46bf353a9812e772d3aa053b734fddf2d00499a5dd51eea7d02141a76da6714ecd500ee29c0ed5a8f269775003f347f153697d2801f48ea366ea6eea52db92801233f3d581f76a92b6d6ab20d004ab8ae33e2bda09fc32193ef44c5bf002bb1ac8f15589d4343ba8b2df70d035a33e6374567e959c57ccb8dbef5af77098259226154618c79f1ffb26933b228ee3c05a5f997266c7ca95e8d2a26c1bab1fc2562b069a8d8fbc3756d4b5e0622a394db3dca71518a4606b7746dadcf95f33b7cb5c85f79aabf31dcedff8efd6bafbf412ca5dbef7386ac2d42c4dc82987f9bafcb8adf0ed2463562db38ebc98b4a77ceb27fc0ab3ae6e5998aa0dcbd82f4aeca2d02367e916d5fe1db9ad08741878fddafd196bb9558a395d1933cc44177290d8dbb85482ca7e7e56af565f0f5bb0f9a34a85bc2d6fbcf949e5d5fb7899ba124799456664caafdd5a9fec12a7ccbb997fbb5ddcde1b5594b2a7cdeb4d8f4111b96ffc76abdb448f6523898524e1622cadfdd65ae874a9a68b0cdfc3fc5fd2b617c3b1ee2c116ac43a518a52cc176d4caa45971a722c69f712461917eeee0c2b7bce2d85cf6158b696de5af3f2f3bab4ad99a43b9ab965b9d51d8dc865564a918ff76a9c2e16ac6edddea4a242db7ef531ae02d359ea09a8023bbb9f90f35cddfcbf2332fcdbbf8ab5ae51994ad507b2de02b6edb5516912d1c5dc59cb7d336d3f337dc5ecbee6aabe8936edb8e86bd0a1d3a1440aa94efb0c5fdc5dcb5bfb7460e8b67096fe1b9154edad2b4f0c0d81762eefef3575a960bbb77f0d5c8a10b49e21f42561d7538d9bc1d0c80b36e66a54f0340df7a3ff00c7abb4f2c75c53c47bbbd47b7915ec2271efe12b58d02a5baeefef73551bc37240dba1dd1d774f08e3ef3544d6ccdfc0dff7d54bacc7ec51cde94d7105c04953ee9da3e9fd4576b6e82540dedf77fbb5421d3bf87e6556fc4569dac6625dbb3e5c7deae79cb99dcb51b1cff89f4a13c1271d8d78f5cdb7d9af8ab7dddd5eff007d06f85973dabc57c536a62d5a5fef66baf052d5c4e6c52d2e53b287f7856be8af869a7c9a7f8761595195d8eefc0d78a7823486d5f5fb2b554dcd2b8cfd057d2d6f088a35441f2a80b5e81e6cfb12669d45368330a6d359a85a0072d3a92968010669f51d193400fdb49c6ea6efa5a005cd26ea46a6e6801fb6929b93464d002b30a6eea5c52350014acb4dcd19a005e29bba9734714086e68a4dd4dddf35003b6d2676d203ba971400dcd31896a56a502a807252e29acd49ba8014fcb46ff97e5a4a36d001e61a76e2d4cfbb46fe6801db7fdaa6f0b46fa36966eb40064526fa36d271400ee6a3743eb4fddf2d333400c77dad49c52b2fcdba99b76ffbb400f57da3ad14d38ed450330b76e6a5dbbaa2ff006b34fcee15c6750f0e7eed3f75421be6a5dfcd302456a7547c52efdadfecd0049cd2efa8d5e8dc16992499dd4537ef629d400ea553b453158d3aa843f751ba994e55a043b9ddba96987e5f969775003f9652b512b1534eef4a46e1400f0fba8ed512354d400d5cd2eea4fbb45002eea7734c6eb4ee1a9922eea32692956801dba9eb51e6856a604d49ba9ab4bceea007e4d2ab53568a044b4b51f34bda801dbe9dba98b4ec9aa01569fbbe5a8d58d2afd680227fbc6a68cfca2a297ef52c2dfc34016334cb856921644fbcc0d2af7a55a067ce9e31d19b4ad442b47b56550df2fbd73e8823ba5ff64d7abfc5dd33cb8e2ba51b9f3f7bfbaa2bcafef4c7fd93c54b3ae9bbd8f66d0576e990edfeed59918a8f9aab7870f99a3dbbe3ef28aba57cc26be767f133df5b2291b78d97e61f35559acc37cd5a9201503aeea71931d8ca3631afcdfc54f540b56641b455479a38fbd6f16cce48b0b8a7aa8aa5f6c1bbe58d9aa44b9933b7c855ff008156a8c645868d6a06806e2cb48f79b3e578f6edfeeb5345dc6ff75eac91c220b47941a95a456a4dc1681a156118ab31a0a6447754e8b4ae512255945dcbbaa38d4355908314ae162364a8248aadaad44c28b8141d2a361c55c9142ad5392801b8a5185a617db505c5e4710dceeab4125e522a600357353789ada26dab244bfef35353c5da730f9f51effc3c0aae57d88e75dceab14e55ae660f10e9972db56edb77fbf5a304d1cb8f2aed9bfe059a4d35b8f993d8d5e69fe57f7aaac2f22fde3e655f85d64f96b26c0510ab28e3754d1e57fbdb6a35f91bfd9ab0ca367ca6b3b811c8a648cd79178ce0ddad32d7b032feedabc8fc5c776b93575e0fe339b13f09d4fc1ed35bfb63eddfc36e36d7b4eef96bce3e1059b456174ec3efe2bd195b8af54f264eec76ea4c9a4dc2992350403353d6a25a978a005a28cd235002f14645328e6815c5cd26ea5e29acc2810bcd2d33752d003a9bbe8edd686a004dd4b9a6b3535b34012714d66db4da5a004c9a297229ac680168e299ba96800a6ef3f7695d82d311775003956a4a61cd27340c7b61a999db47f152f15403779a379a56c530bd021db7e6a1a99bcd396818990b8a039a76d151b633400fc96a4614ddf49bcd003d9b6544cfb734f6c546edb7ef5003bcda4652c435337fb505cd003d53938a280c5a8a00e583cdc6e45a7abcbe94e89c3aee534fe141ae33b462bb7f1252ee3e94ab8a7d3248f79ddd1a9dbcfa538669ff00c5400c56f6a7ab0fe2147dda7eef968019bf6f66a72bfb539a9deb4c923f33d9a97cdff65aa45a72d508633f1479a7fdaa7f142d00337d2f99ed4fe3752af5e94011f99ed4bf68f66a9580a4650bda81106fdce7865a7a5c3212ac2a5650d55e4ddc63ef2d049335c0f46a5f395a8460c9bb14ee3f8850001d1a8dc15a976251b0530137d2ee1479549b16801d91451e50a0a2ad30245614b914cd828f2c52024e2978a6ac6297cba621cac29cae299e57f78d1e57cb400fa766a2f2fde97ca3fdea009377cd4aa4545b3dda93cbdd9e680249586da64676bd2793ef4cc6ea00b94ea81626fefd3d11dbbd00727f13adcdcf87191433366bc2cc5f3ed5dabcd7d27ae69fe7e9973e6cf6f0fc8cbfbd942f6f7af9f2fecfec933c5ed49b3b282b9e9de113bbc3d6ff00ec8db5aeb1561f81be6f0f43f535be9f32d7cf56569b3de87c28ad32fcd5048420ab1735cf6aba84b1b18a10ccd8a98ee596a6efbdd556b1ef354b1b3cb3c8b5cceb979aa2a6e691a25ac2b086779ccd36f913d6bd1a542eaece6ab57974475773e31f291daded5e455058b3560cdf11351918fd9e3db5d05b585bdf68b3abbaf9b2a9f97fba3d2bcec437163348ad1aef43b7e6aeea7461d8f3aa5699be7c65ad48c8cf1ed47eec870d5734dd7b51bc982ba45fef2e4735cd2eaf71e5a23a26c41fc5fc59ae8bc24b1cb726eee2448d106d45db5aba30b6c64aacfb9d569baa194f9528f2e5feed6c2fcc057257f73fbf0f6bbb729e36ad7576ce64b48e561b5996b82b4145e877d19392d49e27dad57a223159917cc76d68c7f74560d9ba2dc442d594615516a74c5004ac698d49ba8f5a0456b8fb86a8b62aedc74aa0c3e6a6055d46e56da1676fbab5cf7d8e7d4c967666ddd22ecb5b7aed84b7d1c2911dbb5b71aa90a5ed8ee6485195bf87757451e55ab39aba93d2279c6ab62cda9ca8b26ddafb76b535b421244aeb7b148ecc57c9d9f771ef9adef10e837b7d7325d5bdafccfd55ab0a5f0c6a3111ba0976e37615beed76c671b1c52a724f6121b4688aeedaafbb845eb5d14d677ba67ef41961e037e06aae89a2cd6b7c971710b6d41f77fbd5d35e3dc6ab8474db12f455a99ce25429cb73234df1cdddab84993ce5fef576fa57892df505565f95ab945f07ee7dca9f2ff76b674dd125b6c2b7e0d5c35941abc4eba7cdd4ec95c4a0559847cb59f6113471856ad28ab899a838f90aafa5791f89232daedc6e3f2eeaf5f74dcb5e4bafaeef11dcab7f7ebaf07f1339f10af13d8bc0da77f67e8f6ed8f9658c574d5cbf86fc45a7ae8f6d6ec6557450a7e5e2b7d2f63910327ccb5ea2927b1e44a0d6acb19151b36e6a88dc8f46a16614c82c22fcb4ea844e297ce0d40129f968c8a8fcc1b7ad1bd68024cd379a6338dd479b400e6cd2d47e60f5a4dcb8fbd406849bc51bbfbb51b30f5a4590530d0929b9f7a6f9d4990df36680d07e4628de2a3e3d5693cc0a680d091b2d4de69be70a3786ef40b41ca451e6d47c7f7a8dc3d680d091be61f2d46ee55691ae028a85a5f30eea009572d4f5c2d350ae3ad1b87ad0049bc5358ee5a8f78fef2d1bc5500ad9a5a378c0a637d6a4097229188a8b6ffb54291c5500ec96a4c9a3cd1ba90fcd400bbbfbc69db8544c3de9385ef40c9777cd51b351bc50c7ad021a015f958fcb4ef92a3da703753400b4012ad07348ae1697cd5634009c87345233f3450072913f9476ff000d5c521fe6aaf22ac9f77ef54714c606fef2d719da5ec514d57ddf74d2fde5a5701ffc3b68a62e18d3e9dc4494546a7e6a5fbd45c448b4e0dfc351eedb4b4c09a9bdfe5a606f9a9fc532476ef9be5a5dbef4dddb696801e0d2f0d51b75a755087734ea8db34e56a043c1a64a876d26ee7a53d6802285f69c354cdf5a8655dad4f89b72d003f753f3518f969775003d5a8c0a66ea76ea602d2d37752d003969d4ca3b5004aad4aa6a25a70c2d3025c8cd3b75459feed3b774a091d9db4bba99934a31400edd46da6f149be8024a88e158d397e6cd31fb5005843b94541a8ea1fd9b6de6afde6ce3fd9f7a9223c5733e36bb2b12c4bfddfe75cf89a8e30ba3bb2ec3aaf59465b19d71343ad2bec9199f3ceee4b579c78874a9b4fbc9770f958d7530c92d9b44f11dad9a9fc676cb2e9c6e366d6602bcca3564a7a9f498ac2c147dd27f0012da0edfeeb9ae8d2b98f87adff127997fbb25751b7e5ac6bfc6ce587c28ab3fcd59b3588e5ab51816a8985444b398b9d0e3b994b4bf354274189576a0f97b2d74b2c1baaabc256baa1376b1128a6734da24cb9d8fb56b3a4f0925e387ba8f737fbdcd760f11a6794d5d11ab24612a717b9cbdb78434f8b2cf023337e35a70e9b6916365ba2edad4f20d392cfda9bab27bb12a715b2208e38d5be5856a56e95656df62f4a6bc3b8d67291a24470a1abc95147155955a8b956244cd588a395beea352dadb17615d7e89650c637327a55455d99ce5ca8e45e2910fcc1a98e7dabb2bfb5825b8ff0052bb7fddfbd58da9693b50bc54dc752233b9cf3fcd9dd555d39abaf95351326ea2c59014dd559e1ad155a5fb3865a6062b425691add5fef85ad66b6a635b7b517033d2c615fe05ab296ea9f742d585b4f6a9d2dc526c9228a2ab30c2b4f486a60bb6a188785fee8a987dea626315284ac98873636d7966b10f9fe2a9131f7a40b5ea8df32579b4c3778c2666ff009edc574619d9b665555f43b1b3861d36d879aeabb6b5fc39abc72dc1890fc8df2edae6efd2459833b7de14ef0db14bdf97fbe2884da95ceba9868ca93bf63d176fcf52220dbd29129eb5ec1f300a07a52ed1fdda5a46a090da3fbb46c14992b46680130b49f27a53a9ad4c2c1b15a91a25a3751ba80b09b06ea4da3d29fc6da6ec14084d8949e50a5dd46fa00698852796be94fa0e28023f2e3f4a5f2452eedadb7146fa004f2c530ed5a937543361be55a0647c3374a902061f30a1129db82d021ad18a3c914e69686a0633cb4a3c98e9d8a4c85a004d9fdda4db4ff32919f755011ec1eb46c56ef46c348d400ad185a361a76f0b4bbe801b8a4f2d7ef669594d339cd000d126d2d9a8cf999db8a933b7b52abeea008f96fbd48abd39a9194e7e5a4f2b6d0023421b14c92255a7ef55a63932b0a0088a9639c515304e28a9039def48f1071fed51472b5c67691248d13ed6ab88e3f86aac89e62d471c8623b6a80bcd48a4b66911d64a76da043beed3f7d4694605004b9f968a652eda621fcd2a1db4c56a280250df352a1fe1a8a9734124f9342beea8b79a5a62255a75440eda55aa025a40fb69b4ea0073aee5aaaaed1b559069b200df32d021c18b52ab5470bff0d49400ea5dd4ca5fbad400ec9a729a6f0b48bf7a981252eedd4cfe2a2801fba8ed4ddd4b9db400f5a7035152d004dba96a25cd2e76d0492526e14ddd467e6a007e69af4831435002c6d5c9f8d9f75cedfa57508db58572fe3642ba8eefe1e2b8f19f01ec64ced5fe473f145e6cf0a7bd5ef16dc07d2caaa7caaa169fa6da07bfddfc2a9ba9be269a3feca95563dcd5e5c7e247d1d7d62c83e1f2edd36e17fbae2babdbf25723f0f9f75a5dfd457608bb80dd4ab7c6cf361b15ca5567fbd57993ad54997e6a988c848dd51bc63d2a6c1a36d6f1132b3474cf2aae14a4310ad9321957c9a9162db4f029db68b8922bba7f0d46c9f355adb4ddb499488912acc31f22983e5ab16cbbbe6a43342d53a5761a3a06876b57316717cc2bb3d0d0326d295ad3dce6afa229dfc5fbe3b6aacb0ee52ad5b37f69f39602aa35b155aa96e6507a1c3ead63f669777f0b550006daec758d3fcfb735c96c31b956a966c88f6539453d969291434a5279752526da4031529e143514ab400ea72d0a052eda960392a74a856a58c566c82565f94d79d797bbc55b97ef34fb6bd15dbe535e7b6d993c4b337f764ad68e9725abb3abd5600d144f8fbb5434a3b2fb6fbeead4b97f36d8ff00df5597a78dda971423befeeb47a44446d14fc7cd50c7f2a2afb53f7d7b28f9096ec7eda29bbb752e29885622839a8d88a4692810efe1a15a9bbf75230a0093753726a3ddb68f36801f9348ac69acfba86a00792314d6a6d22cb400bb9968c9a4dfba92980f622919aa36a699428a001dcd227f7a983e6a9b77cbf2d002d271ba98c0d031fc4680159b6d1e65195a43fecd0038396a36d45cd0ac6801cc76b520734bb87ad2311fc3400e572d46cf9aa3c9a326a807e02d377eda5dcb51be3f86801fe696a2a1f9e80a76fcc680246a6f9a1586da4fbbf7a94e3f845003d642cd448e17e6cd57673bb6fb52aaf1f31a901554eeddba977eda7ef555db51bfcd400f32514d5048a280399cff00769fbbde9be48a5f285719de38633f2d35f0ebd68f2d76d22c0395cd00442468986dfbbdeadc53891473512db0f5aacc8623544334f7ff0074d2efaab14418065352ecdbde81136fa45ff64d45b3e6eb42ad004eb4a0ed5a8554fab52f967d681325a72d40a9ef4fd9ef4c44b4e077540aa7fbf4bb4fad004fcd3d4d4182a3ad1b5b775a6059dd4e535579dbd69f965ef4089f9a7557dc5bbd2fcdb7ad500d7cab9a9d25120a81d0d429f2c9408beb467e5a87637f7e9e11bd68025dc297f86a1c352fcd4012e68ddf2d330d4624a009376e6f9a8a67ccbda9d4c0766977eea673e94a33b7eed004942d440b2e6972d4012e68a8b269dbbda8247ab6ea77f0d43bfe6e9479adfdda007565789ec85cda25c2ee6fe13fec9ad1321fe214ab28c344f1f99137ca56b2ad4d4e1ca7561310e854534723a3bb2a5c6efbca9b6b375a7dd6d227b56f4b69f63bd9e1fe175dc2b07504fbd5e324d4accfadf68a71ba19f0f9cafdae26f6aed9182ad713e124f22fe64cfde5dd5d9fde02a6b59cae7272d95874a42d556a9deabca7ad4445619c668e2a3c9a5fe1ae8892c73537069d8a51f3559233673ba95a9db6929811e29b4ac6a099f8a063d4ef6ad2b18eb36dd4d6b5abedf96901b3691edc735d6e831b13b86ddadd6b8e8a68ff0089fe6adbd36f3cadbb1d96b4a6d2673d6839c6c8eb2eedcb42d592f1535efe465e5d9aa26ba8fb9ad6725267352a5382b3126b75917e6ae43c43a41809ba897e4ef5d735cc78eb55ee123b985a26fbac2b33a6373cfd5b72d153eaba6c9a55cedfbd039f90d570dba9142d3a9169db69011d22934f6a4ceda007c552544ad5286dd52c0728a911aa35a917e5f9b150c9b0a5fe53f4ae1ed22dbaddc4befc576729fdd337b1ae52123ce3c7cd9a70761c56a6e24be65bb2fb559f0f695ba612b7fbc6abd9a6e4e95d5dac4b6d0aa2ede0574d0a7ccccf1789f650b2dd96c3d2e454791431feed7a67804948cc734cded49bb77dea0924634d62292a3c8a6049b8f34dc9a6194d1f7a810f6229386a8da9ac68024dc568ded4cf30d272d4012ef1fc4690b2d42c2933b6802467342b9a6799ba9aec29812f983150ff00ac6a8b976a9c7cb40127dda19cd303d1ba801ead4607ad45cd3779a0095982d37cca4de29386fbb400f32eea6edef51ed6a371fef5003beed28942d2655a8ff768024dfba931517ceb49ceeeb400f6a15c2d27cbc50dfecd003b3ba976d3194aaf4a66fdbf78d0039b6d37cc38f969ac7cc236d48222a05002243bbe663f3669c6214c3b9685efb8d00378573cd3f785c52ae1b0bf2d3187f76a86481c13d28a887981473450073ec69dcd47c6deb4b935c0770f0dfdea5fbd51efa55eb40126e39a6c88645a46f9bbd2e4d3208626313ed6ab68e1c6ea85d448b5023b44fb5a803438e28e2a2497762a4a007330c51bf70a6e451915421dfed5287eb4ccd1bbe6a0095982d00d47ba9377cb4124bde954f1516fa72d3024534fcd439e36d1bf9a6227dd46fa87753f7f0377dea009438a8a64e772d0cd4b9dc2a809609777cb9f9aa4dfc567a398e4ab7bc30a00b008db46f1baa10f4fcd00481bad0adcd46a7834bba8025cd0b51e4519a044bba80dba999a334012519a66eeb477a00753b75328cd003f8cd2ab533775a01a0073ad3226dad4fed516edad4014f5c41bedae3ea86b96d520757e95d96ab6e2e74c957f897e6ae72c6e1a5736f322ee4e8fed5e4e2972d4b9f49974f9e8a5d8c5d05cc1aa6c71b7d2bad0e71b6b9ffb305d4c4ea2b722fbd5c92d59d724586ce2a129561146050e9d5a9225a28b75a76ea1c734d7f96b7899b169d4d4cd297ad481f51bfcab4ecee5a8dfa500412b05f9aab0ccaf525c7434ed3d4365de828b90aeda7f9c12a2330fe1a898ff00166802dadd96ef5721d464503e7ac54946ea915cfad5a21a3a14d565c7dfa47d564e79ac4494d3bcfe6ac8b1a8dac4aadf29abd67ab16215deb96b9be8605dd2c8b1affb4d8a9ad6f22970d148ad52163b0bf48752b292ddbe6dc2b8b5492095a27fbca6b492fe45fbaf546e6532dc17fe26a403b34fff0078d455250215a929696900629e30b4d5a4ddb5aa5812eea71fbbd6a34f9453ea44417e7cbb39597fba6b0348d3fcf4f373f3679adbd532d68517ef31a8ec61f22dca2fa52405eb089649d624fe0eb5b4b1ff00b6d59da24222466ad4c8af4b0cad1b9e463a7cd52dd8361f5a76d6fefd3371a4f31aba4e224f9bfbf4ddc7775a687dd466a80773eb436ea66f3485ce6801ccc7d6939fef527deef48c6824760d1cd304a68c9a6039beb4993eb49c6da6e462801cdba85ddeb4dde69558b77a0042927ad4382cdd69647ddf2d39176d000be62b52ef939dd4ef3290b07a004dd237f768dd273b69d4cde17bd001e649e948accd9e2a4f312b13c47e253a2f949143b9a5fe2ed4058dadb263a53774abdab0a1d6afa484ccce9b71b82ad3f41d6ef7509645ba836c4bd1e80b1b3e6cbfdda6ef3e952161c6da6d02133228fb9479d2aff0526f3fc46943ff000b500279d2ff0072937b37f053b3bbee8a4c1a0626e9bfb8b42cd3aff0ad1bcaf7a46b9fe15a02c2b4f3606e0bd6987cc660d48adb9be6a955c6df9450162359265ff966b4e59aeb70dd1d0dbb70e69379e99a001a56fbce9485cfa7cd4f599693fd666980d47653f28a7f9b2ee3b9298772d203d396a02c248ecc7a35152071c7d28a00e73753d58545bcd1bab88ee25a50df2d460ee1d69436dcd003f238a5fe2a8fcc146ff9be5a68926ddb4ed6a6ba8914ff007a9bdb6e69dbb6e2a844292344f565243514c04950898c476b7dda00b8cf4f0dbaa1497753b750224dd4bbbe5a8b268ddb7228024fbcd476a6668de29923d69cc7e5351eea50e1b3400f534676fcb4cc8c51f7a98126fddf35399cd46d465bd6a844bba9c0d42adcd2efa00748b4e866fe1a66ea8a4ca1ddba802f6ef9a9caf552298320e7e6a955e80270f4e63505287a00995fe6a731a8377cb4e46a044aa4d3b7543bcd3b75004bbbe5a2a2dd4f563401251bbe6a62b1a566a0092914d341a3eeb5003ea36f95aa4a8dff00bd400f1f302adfc40ad6235b089d9b1f37ddad856a86e42ab6fc7cad5c18d8376923d7caea24dc59873a6d42d566dfe60ad557529872ab53d8b1f25770dacbf29af319ed48d04fbb4e276aeda621f96959a8332ac95170c6a696a1c7cd5bc0863f342d0b8a5e2b524322992fcb4ea89da824a937cd504571e448518fdeab6c959d7b6a64f99681a341661f796b0b5abbbabbdd0dbcde4aaf56ef50bade479d9237fbad446accc59836eab8a066169da4eada7dcf9d15fdc75fbacd90df9d76163a8492205986d7515498b32edc6da743f2d6a657357ed673f2d364b89547c83e6aaa943bedef40183a8787ae350ba3717770f2ede83b2fd055bd36da5d2a65f2a46d9dd6b41a66aad2d9cd39eacab43d80e822d463d9f315a92da4f358bd63d9e9455870d5b905bf9482b36225ff00669d51f34ecd480ecd395a9b42d00398f142b5359b8a456352c09d1a8ff6a9ab8a5a422bdcb731fd69e887ef54375e634cbb519b6d59b6566fba8d424dec2e648d3d38fee4afbd5acd410c7e544158fcd526fdb5ea528b8c126787889a9546d0ff0030d26ea697a4c6eadcc0929a1be634c7fad2ef1400ede291b2d4d6a4f9e801d46ff6a6034ac45003b3ba9369a4e69bcd048efbb46fa4c8c52d328767754533edeff3524cdb17ad31016f99a801c836fccd526f4a6ab0a38a091ccdbbeed27ccabba9b96a37ff007a801dbf77cad47eee99c629aca6801f8a64d6d1cabb658d5a9de695a5dfbbef1a00e4b57db6da90893f76a40fbb5d6428ab146abb7a0a8a5b482421da3566a7a663a851b3b9d152b73c631b6c3db349bcd2798777cd48de5fad5988ef9286036fcb51329ddf28a3cd6a007ee2bf351e671f3533cd18f9cd40edb9be5a009de7565f94509b57e66a6c48aab4329a0099b18e94cc95a8fce3b680e1976d0049bcff0011f969df2d42f8dbd698adb7e5a0091976fddfbb4ddecb4df3777cac28da39a0099a6ddde91b18aa8fd36e3eed3a390a0fe2a00579f071e5b3514798adc9a280311a2dbde8c7cbd69cbf32d15c67602a528465ef48c450ad400a075a369e39a41f2d2ef0c4f14c90589a95837ad26e2b4bcb5508065b3cd37c967cf34e5f97e6a50f408ac4340c369ab71ee601b7d46e370a8e37313ed6a00b6aad4e1ba93706a371cd004810d2344dfecd3779e29e1e8018cad46d6a72beda5dc39a648ce690f99c629eb8cf5a39a0427ef29cbe67a522d3b7d3108be67a52aa3714bbe80f54027ef15a9a6292a52e2853f36da00a99689ffdaef560348ca3eed32e23dcbbbf8a96da50bf2b5004eacd4ef9e9777f0d2ad001cd3b95a15b9a5a005de5b1c53b2de94dc95a76ea007734bb8f342b52eea0032de94bbcb76a5c8e2972280115f6e69598d1c6da01dd8a0015cd2331f4a7d1fc3400c562a697795fbb4c63f3d4fc6da5604edaa2bf969bb77929bbfbdb6a814d97322b7f17cd5ad542f536caad5c78a82f66da3d0c0d697b54a4c45a1a913eed2357927bc46f51b53dea166ad60c9687eea466a66ea6b935aa6458567a4dd51eea4dfb6a9087b10b4c751b68cd472ca16a90113c6bb6ab346aad5334c24f95aabcac2ad19ca442e76a9a884a39e3b54adf4dd486dff8b15665764d6cdf2156349b2366dd9a890ee53b68d85bbd315d971230ddeada20c56786318a7a5c336281a66c45f2a8a9b76eacf8a6f93766ac4738c75a863b96168a624c31d68a80b9253d2a057a78340c7d2ad2519db5221fde9eb4c5a7afdda42658b0c2bc8d9efb6aefcb552d621e506fef54de505af4e92b4523c3af2bcdb26a4df4c541eb46cebcd6a62494cdbfed5336ff00b546dff6a9887efa3753767bd26ddcd54049834cdc569bb59bbd1b4ff7e801cac28dbfdda66195b6efa4c37ad0049b4ad1baa3c37ad0de67ad003f2291cf960b7f0d4124ad1a96cd428659cfcc6802756695be6a9f2b5088e451d68292d004cd8fe1a6a965a8d432b53b6b7f7a8017ccdd47c9eb51956ddd29b834012303bbe5a3cd65a45f33d69afb9a8024cab7de348ca3f86a16cd2ab3530255765a3cd2cdf354597a63335202c7c9eb511539e9501693f868df73eab4013f9857ef523cd1edf98d51b8b89a3c2fcb491acb27cd9f9a802cfdf6a9d55547cb5536cab46f997baeea00b1bcafdd14ef39eabef95bef95a5e7eee3ef530257656ef4cff7454655968dedeb401279a568f3837cac56a27576c70b4c31b301c6da0099875e698b26d5f9835337c8b855a46dccdf31a00905c0760df75a97706cff007aabb43d38a6ef2b8e36d031eeb83d19a8a6b487fbf450050c9cd26e3fc4682db6863b85719d63e8cff769bf7a9012abf2d30155a9d9db4cdd4ab4103b70dbd28a4e17147deaa01edf768ddb70b9a66ea75002ff001523aef5a3752d0222490c476b7ddab7bc32d57740e3e6351453340fb5feee6802eefdb4eceefbd4c470c3e5a55a00955c6da4a8ff008b751f7a9922e4f3407e0d3377cd4adfec9a0449ba9c1c543ba8ff008153026c85a375315a9ca4d003d4d0d4d6a377bd5087e777cb504a9e5386a9327f8452ca8245db40134443aeea5c9aa914a636dad56a801fcd381fe16a895e9d9a0097752a92d5186dcbd680dfc340122b53d4fcdb6a1c9a729a00955e96a356dad4eddf2d004b9142b6da621a5cd003f752ab533750b4008ff2b6ea950fcb514df76885f8a009b02ab5e26e88ff00b356370a648bb815ace71e6562e127192922821dcb431a60fddb95a735782d59d8fab83528a688dea276a959b6d40edba9a1b426698e68dd51b56c88681df6d577b914d99ab3de5f98d688c9b2f9bf0bf2d4335e0ddd556a8853293b0d2c561233ee7ad122352d2b6fa5f2da9711408158d46f7a17eed5a8b1589847fdea9768642b541ae59a93cf65ef57cac394b2f6f26ee95225b6d5f9aaa25d499ead48f73267e676a7cac394becb132ed53491c23755059be5ff006a9e97457bd1ca271341e19170cb5009a45976b3d116a5fdeab28d04b86a868868845e1e79ab16f79b97e53bb6f55eeb515cc6bb7f86aa08fe7ffc781ef52c46e44fb854eb546cd8b2fcdf7aaf2d64cb44949c6693f8a856a40488df353989c54710fe2a9625df205a71577633a92e58b6cd0854ac4157f8453d49a62fd68de2bd547843db14d5a4dc3f86919da9923da5a46a679a29188fe1aa10fc95a5f37e5e95164ad1e66ea009321a9bfeed318a7ad3735404bbc51bf70a8b79a438a05625a6bbed6a898951d6a29262c76ad003e57f3582a8a9e30b1ffbd5143888734eff0069680265634be6541bcaf7a5f3568025e29ac6a163fdda1a465a604de67f7851b8377a80c81bef1a463b85004b9db479a573baa00e56869777dea009fcd0dfecd3598541b97f84d37735004d96a3cda8bcdfef521756ed4012310d9a8269f6fcab50cb3167da94f893fbdf7a900e8a2f31b739a936eda672bde916539dd4012f987775a1bcba8f7a5054ff000eda0090e7f8452172bf2b545e732f7a5f355bef530242fba9871f75698fea94cf34ad004be66da4f307f11a85a60a4d07e65f976eea009d7cb6fbbf37151f3bff0086984b70d9a4dfc95f99a8192ef6ddb5beed23b2b28dc7e6a8cb0e79dad55bcd667daa775202cca55319f94d15179258fccfcd1401991b96f95cd4ca8d50baff00152a5c153b5ab94e92c7e34ad9db4c621a9dbf8a001569dca8f9a9bbe977965a042942b46d3c52060b4b91408508686cd27987142b5500bb4d0772d1bfa53b750037f79b7e5a6488ce0eea9378a5de3ef50053f366b63baac4534b22ff000d2b8128f9aaaacaf036dfe1a6497bce9171c2d0aedfc229824dc81bfbd4f56a003cd2a7e6a5e57ee8a3752abd31073ba9771e770a37eda5de185500a09fbdb69779f4a6abfcd4bbbfdaa005de5a9d9f9ba5303d3b7f239a042b3bd1e6b2e78a4c8a5de2802293731e94e8ee646f9714fa88feede8027de7d2a40e5947140656c353f786a004566a76e66cd0ad4b914006f3b69518eee9481e9ead400a1be6e94f56a653d5c5001cd3b77cd4d67a4cfcc2801eaf4339a4de28df40034a7078a6a3ed229c583542ff002b5005c0f46e34d461b7753b7548ccfbbf964ddfdea666ad5f2ee8cb567ab57918a872cefdcfa4cbaa73d2b761ee6a266a731dcb506fae7477d85a63d14fad62672467dc2166db59970e6d98ee1f2d6d4cbb9aa95cda09508615bc4e7922943ac5aff0ba6ea49b55f37ee9acebbf0c47392cbf2b7f796ab268b75012be6332d6f1b024697da4b77dd47da22fe2915557fbd5561d264957f7b33d584d0a06eecd5a268be5422ea56abf2efef537daa06c32c8b42f87e26c715693428b6ee5aa0e54673ea10c6555599b9e5bfbb4e3a940dfdead25d1e053b5916a61a4418d9e5ad30e54641d4a150193737fb3b699f6f66ced81eb7469b0c6df71697ec90afde4a4c9691cf35e9fbbe5bad47fdb6d6cfb763eeadf92de293384a8a2d2a367ddb16a1b46323322d62eee9c2790cabeb5bb69136d1b8d0ba7c684362adc516dac64c92d5b8db562abc6db6a5dd5931a44ab4a3ef5460d3d6a42c499a96d70ceced55cb6eab9142140ae9c3c6f2e63831d53963ca4dba97cca66051b0377aee47923b77fb549b8ae79a614a4e2980e66a37063d69bb375279436d5210fc9f5a42e29ab8fef53766eef40c7645193516d2adb734350049e605fbd49b854672df74d5699a446eb4089a499d48553524595f9985558a22d86cd4d97e39a00b1bc351f8d576596915d9315404e24fef0a3706a8b7b377a6b6ea0098a955eb434bfdea837c8ad46f66a009b7ab0f969ac4ae594d4586e76d33732b0e568026121fbcc2869035445cd34ab35004cbf5a0395355ff78a6a3967923fe3a00b86e1556aa976958edfbb502ac939dcd52a093eee680274c22d3b29fdea84f99fecd306e5a0658dc568596a10d236554d26d91bb2d004cd8fbd9a4decb55be65ef52659bbd0049e706ed4361ba15a8b6b7f105a673bb77cb40133332d234bfde15187666eb41f33f8b6d004bbd7f86a2cedcfcad519dcd9d9b6a2926651f2bfcde94016bed055be61b683346df76a8069650573f2e4a9153c6b22b755dd40c91537b6e63f2b50e0ab7cab5117973d691a599543395a00b025e3fbb45442563c10b4501633d65a477feed560e5bfdda3cdae7372747643d6a7171b875aa1e76ea6f9bfdddd401a2d353bcdacff00b505c2bd49e77cdd681177ccddde859783cd53f3297cd1ba802e6fef433ed1553ce2b4a65f7a00b66514bbcd5359051f68f9bad302e34db6869b68aa7e6d2f99ef40173cca64a04a0d5759b6d2f9deeb41243f6892da4ebb97357629c361aa9cccb28aaad70d6ddb76da6236564a779bfc55990ea1148a369a996f178e775005ef37a71479b54fed0abde97ce0df366802e33d2aca3f8aa9ef1b8734bbfde802d2cbb5a9fbfe5dd547cea72cb5422e79836fcb4ef36a9f9a170d42cdf375a00bdbea32dbaa0597aee3479a334013c373fc2d563ceaca92555f994d4d15e2b2fcc68034bcca5596a8fda06297cedb40177cda779c6a9798557731a3cd1f76802ff9d4a26dd543cce714ef336b5005ef376e68f36a9b4def4098d005d1351e655412fcdbb3479b4017779a8a496a25929933fcb401a10cdc53fcc359b6f37cbb7353acb52c68b4efb94ab5664bfbb73565a5aaf39dca596b93154f9a373d3cb6af254e57d48f79a631151f994d66af28fa5b1233519a859e9d9ab4c89215e9bb3753b76ea555ad53307122f2c544d12fa55bdb513ad5a64d8a2f0ff12d3166317de1baad3e6ab4dfed56f0604b15ec6bb78fba6a71751f1b6b2fe55c5432dcaad6c897248d63763751f6bac77d5a15217ef353a2bb32e768db5447b446b35c96a154b7deaad0b7cc38abf126e5159b62e7b84515594887a522254eb594990c66ca6e2a47a6d45c561a8c56a5534ca5fbb525a449baa4dfb7e6a8b22973fc3484cb16e3cc70cdf756af292b5562c46812977fbd7a34a3cb1b1f3f88abcf36cb3e6d3778a87cda4de3d6b54604fe61a6f9818d43bcfad0d21c7cd4c44db87f09a6f986a1ddb9a8dc714c094ca2914fa3d44cf49914c2c4be615c5359c545bca8a6bcbb7e66a009649020dd9a857329dcf50eef364f9beed4fb768fbd4089bccdb8e293ccdddea2f34ff10a6ef5feed30272e547ca693cea8771fef52097fbd4c09b7eefbb4d6765ef516e1fc34bbca8a0091a40df78526fddf3542d37f7a9376e1f2b5004fe6156eb49f681fc550ef655f94d359e80262c1bee9a0b95ef50ee0ddea19673b8221a00b0f73dbef3531626660ee29890fcdb98fcd52e4e68025f3bf871b69bc7ad45bd1b3c5237ca3e5a064be61fe2149e686a8bcc3ceea6ef56fbb4013f6dca69a252b51f2abf29a166ebba802559119a919bfba6a0dcad9a1bfd9340137985450d20651c557de634a3cd5c5004f9f97e5351bca50540f305f954d332cff0078d004bf686918aa8a6794771663ba90feebb53d6e371140c79dbc37f0f7a50c565f97e6dd506dfe2cd355fcb2777f15004ff683bff869c4efef591aadcdc451ab5a46b2331da7fd9155ac2eeee473e6bd051b52f0df7b34567f9864624c8ab450045bc52efdd5082314e0dd6b1b15cc3e806a35ceea565a2c171cff00bc5db4212bf2bd37eeff00bd4361968b0ae4eae36d2b1dcb55d1cc752097761968b05c937066a76efe1a894d29945160b8f634bc547914668b05c9011cf14bc545be80ff00c59a2c172461f351c533268f5e69d843b68a6b47b81a3751ce28b010c491c4e5587cb569123c6ec544f106151c7315608f4c0b4c829db17d29aadb8d2afcb400e0a3eed3b68cd337d287a007a28dc695aa356e3ad2eedcd400fe29dc7151b3f1fed52a35003f8a5c0c5301daa68dd400e283d2a1550b354ca6a3917826802d08969db4557b79370dac7eed4df7b3401270ca6952a206a4ddb6801db7e6a7363fbb51fdefbb4fcd003d5450ca334c46f968df40126d3ba864e69aad4fddba8189b0f3cd35d3fbc5aa55a46ce6a6e3b15e18b749b6bb8d0bc3fa41578af76dcdde398f79c45edc77ae245cfd8dcdc2fde4e9f5acfb5d56eacee45c45336fddb8ff00b47deb9aae2541f2b3e9328c8e58ca52aadfa1a1ab6b561a7ead73633472db344d81dc7d0d5945120565756571b832f3d6b03e2687bfb6b2f125bfdd7c5bdd7b31fbad5cbe81e2abbd2255453e645dd29f3dd1bcf285cbcd0d24b747626e02ccc9bbee93526fdd5c96a9aec716b171b7e589db785ff7866b4ac3568e7fbaf5e5ca9b8bd4ec5b6a6e50ad5024e1fe6cd4bb83524291327dda72b531314eab462c733714ca1a8ad110c8f6fcb504b106ab1495bc4ce4516b5fef5539ec033eec56c6ca8da3ad533091cdff0065379accdbbad6adb5b053d2af791528876d3e622c470c3b6ae26156a35fbb4f5a865225ceda37d369154d66c63e9eb4c45a92b31a10e28a2929162b1a7c39696abb36e6ab36fdeaa9abc918e21da9b6582cdba98c4f34ddfef46f35e99f38c7ee66ef46e3516fa4df5421f934b96a8fcda4df4012ef3cf14d5639a66f3fc3486614c0937b74a63b9fe214dde3ef29a4f33750035a468f3513cf24bf7a9259bcd6da952a2c6a36d021eb2fca17cb6a1a5f6a0c9f2fca69bbfe53ba801de61a563ed4c4233526d6eb4011b49b68f34d3e51b7e66151770d9a60399c7a3533cd39a3cd2a4eea6b3c6ddaa80779a79e2937aaf76a8cb95a4f34b7de1ba801de69e76d35ae7683b87cb51bc91f3510533fdea007999a5f9947cb5347208976ecf9a9a9f20e94bbd585003fcd2df32d279ccadf36ea8f71fe1a3cef51ba8024f38376a4dc777cb4cdeadf32d279a7eed0039ae0afcac29be77cdd29af30560b8f9a838f5a007e597ee96a4f3cff0010a66f349bc5031e650d95514ddecaa5b14dc2a8f94d33ed27eea8dd40035e155db8a64924d283b452c51061f37dea94308fef6ea00851caafcc9f353959aa4fddc9436171b0eea004de54f4a6fde53c53b70651bbef544edb49fe1e28015d871b69de786fbc1aa22e57a1a6bcbbb1c5051236301bf8aa32c17fbbbb34d2777caa68595b8a0097706ea94544ee1db19e94548141651eb4ff00338ff69aaa238ddb6a546148927f37f868de2a256dbf35394d004bbc328a697db9a68f9a8e3d7750038ca36d33cda7ae28e2801cb32f1cd2f982a37456ff007a911fe6f9a8027ddd7fbb4b914ce39a55216900ec8fe234be60a4a4da16801dbe8cf3f29a6ee0a69680158d2eff00f769bb3de9aabb69812ab8cd324dafde9760a022f3400c49fcbf95aaca4b1faf6aad243bb38a6db9dbf23ad005cdc1bbd2eea8f0295579a4049bd7d68c8a67183c51b05017245614bbb6fdd351edf969cb86a02e481c62977547b5697028289323279a556555eb4c283146050047e608dfe5ab2970b80d9a81e30c3a5240a3eeb5302e6f1fc34ede29800c0e29768c5201e8db969ca7a53360602955375003d48a5dfb98526c153db5a1b999214f99dcd26d257638c5b76449676935db94846edbd5bb2d6e2f85a38b4d6d42ef536554e0c71459adfd2b4786c6c05ba8f98fcceddd8d53be88dac134339636f3291bd7a8f7af3258d6e5a6c7bd86c0d269296fd4e426b8d1d232d15fdc34be8d10029b6ebf6c5fdccd1371fc4d8ae67c4da6dd6917997f9ade4e62951b2af5068b78b14f99cfc8aa4e3de8fac4ee7d8ffaad83a943da523775f89ec6486de565dee9e636d6ac966aa73eb12ea13cb7131f9c9ffbe71524737f13571d49b94b98f770380584a11a4ba1af69a8c696175a65e41e7d8dd2ec953b807b8f715e6ba9d85c6877ad6d2cde6f1ba3997a4b19e8c2bb317b14b90922b3553d661867b16f353ccd80b45eaac6b6a15da7cace6c560632bd486fd4e6359b92f730bb1f99a04fe58a8ac75192d1fe534dd6dfe6b6e1555a01fa1acf563c73c577d935a9f213ba93477fa46ba93aaaeef9ab7ade7120dca6bcaa1b892270e9f2b5751a3ebc1b6a3bfcd5c952835ac4398ee91c54ca0563c1781ab4a19770ac4864d8dd4dc549455a21916da3654fb052eddb5bc4ca457f2f6d2ec0bf74548f8a65598b1516a5515087a7ac81a99238c418d3d2dfe5a22a9b7526511797462a5ed4d186cb54301bb686a1b0b50bcb599485df513cb514b7217e5a815cb5228b68db98559472a2aa43fdeab18dd5a51f8d1cb8c76a2c76f3cd2efa8b695a2bd13c124df45478dbf74d15448fddd29378fe215161a9172ad4012ef1eb46ff00f76a163f30db4d646a604cceb503ce73b54d40ef2ee08a69f1432afcd9a009e30a89b54fcd4e673e955d7773ba9db8eefbd4012975c7ca69be6c951b6ea672cbb94d004cb70370f96ba2b0fb3c9086f96b962245fba3754b6f793c0d4c0e8b506b5588f2ab5ccb4bf3b73f2e6a5b9bc96e40561553f79f7714d089fcf349e67237543ebba93748b4c09cbfbeda8e59cc67ad5579a476daa29511a802cc4859f73d4a5c2d57df2d1e67f7850058c95c35359c30aaedbf751e63d004e1f8f94d1bf6fde155d5b72fcb4d62cb40c9d9c486959f68e0d57de7f8a91b77ad004ccfd770a4dc3f84d57f36456a6b4a7d6802def2bde98d3ad50792567f94d489f28dd40160798c7767e5f4a911957e5aa9e7329a72c85b3ba802cabf1f2d2f9db73bc6eaaddb729a6f9acc050058de197721a3cddb8dbf35556cb63fbb4c2ecabf28a0a2dbdc0dc77065da699e6867fbfbaab7da4b7cadb69dba351bbef6ea00b12bb72cc7fd9a6b48b83ceddd557ce68d76e3bd34cdbb0d4013aca6363fecd3fed3d51855069d987cbe9f7a9627fef0f996802c3cc0b9dbf28a2ab9f747fc28a00853ad3d58e2ab98cab756a7843c54104ea454993508cafcd4e03fbc680245c7f0d3b7544b9e36d3feefcb9a00913e534beab4c6142e7775a009173eb48ca1bef5336d3941fbd9a003694fef6da911d699b19bbfcb4c646a009d5a979e56aba65bbd4dce035003b86c51bb735432c8b07ccef482fa16c2ac8b40163d68eff30a4fbcbbb34aa8d400a3ef53f07d299b0d3b6b5002ff0016ea64b1799f76a4c1a36363ef5032385f6e11fef54f8a81e066a2391d5f635022755a753796ef4ef9e800c52eca5e76d1b595680171bb14b8a3955a76d3fdea0029573ba936b53d54d031365472a15c3ad3db751b24dbb7fbd4809226de95273c553412412edab8a927ad002f14aabcd22a9fe234e546a0a27b6f2999bcddfb71fc2bce6bb3f0e6891d9c7f6b97f792b8f9372e368ae2e15d8c18fdd5615df3ead0bc2a21daccc062b831d51c5247ab96d1e7bc9171ee915ca2ff000f5aa7a8ccb3c263acbbcd47ec319777efd6a826bb14fd64af25c8fa4a38197c68c9bcb47804b05cc5f68b290fcd1b7f31e86b95d67423671bdc59399ed38e71f3464f66af44791655f980db59f2e9e51ccd68707ba374715ac67d19efe131b2a2efff000cff00e09e56b295f91be56a5d42f64b1b16558f74ac3866fe115b7aee872db6a7f6b4b7f2a176e8cdc2b573be22324b325942fba597f758ff007b935dd86a1197bf2d879e675282852a1f14bf038c6d4ae16f04b0c8eaf9fbd5e8ba55faea762377dfc6d75ac51e1392c47fa9567ee6ade8f693da5dfcc1956a315529c97b86b94e131146eeabbdcc7f135bbc1791aff0ede2b212bb4f14588bab03328daf1735c5256d427cf13c5cd70ee8d76fa3d4992a54768f1b6988b4f02b73cc3774ad79e37d92d757a7ea824fe3565af37c6dce2aed86a535a38f9ab9e7453d50ae7ab43721b1cd58cd721a56bb1dd81b5f6b56fc374180dc6b0e569d9926833533cda85650d431ad628ce4c7b3eea6b3d439a6b56a8c18ef376b548928aaec94a9f2b5324bc8f53239cd52df4e59b9a96522f6ef969ad36dcf3555ee76af5aa925e6d53cd66c65e9aec7ad67cf79fddfbd54a6be697eed47126ef998d66ca2c866958331ab9128aaf128ab08bb6a40b49f7aa62df2d43154cf9c0ad68fc68e5c67f09899a334c62686af44f0c5dc1a9bbcfaad0cdfc551b12b54049bbe5a6eef9bad373ef51b3d004a5ea0966fe153f35472cbff007d669118677386f9a8027854afccdf352bbf1b72d4cde1bfbd48cc76fcc299249bcd1e68e3f86a156e6866ebcd0049f8eea6b3ff000d446556a5c86fbb40587f9bfc39a43273514afb71b9698aead4013b3861bbeed0afef55fcd2b51bdd46b4c0b25fdaa0794c876a541e7997fbcab52abaaaeda009910a53b70feed41e6ab679db4799b7e56aa02c292bdd5aa3771d5aa06976fdda4cfbeea4058de291a43baaa9987f10a3cdf9776ea6059570d9a4de7f86ab79bf35279c2802c6ff00ef0a0b71bb3555e70aa371a8dae4cadb6802796e0c6dfdea672ff7a98878a19c7de6f968027f376e38a3786ef50799d39a6f9a371a00b1bd95bfd9a3ce1baab971eb417e0f1de802c6ff00ee9a634dfde1ff0002aaeafbb1f3fcd479a5a828b1e68da79a6b4a570d8db55fcd8d69af30e3e76a009f7a6ef9836dcd08c533cd54498fdd6dcad4af2a7fbab40133dc9dccaa3e5fbd9a13a97dfbaa2c6d62df7b700b41231f31fc3b5005857d8828dfb9fe5fbcd55da5db9fa533cce4bb0ed40cb277e3e4db4556924240294500593132f6a66dabb8155e681db0c8596a4cc8f95cd3bef533cb954527cead40132b53836ea879dd522d20241f352e3e6f969abf7be5a72e714c076da395a36eda39a421ebff0001a3ef67eb4de69cbd28011a2a3795f95a969b82d40c25459d0ab0aa36165b8c8d347f74f15776c8b965a7a3961400f4511ad4b51e1d475a72ab5003b229cad4c6cd38038a007d0b49ce29db19a800f5a46884829f893eefcb42e7f4a008518a92ad532fcd8a64a8597e5151a3cb1901a802daf4db4a31cd46acccdd2a500e2801147f7453a8c16a72834002934ea4c15a519cd002fdea76da45639a3e6db40c491376696072df2b527cf51b2c913eea00b806da7ffbb50c6ccdf3548b48a24e1b14d9b529acedf727d0d2aeea64f6fe7c451bf8857362a8fb4858f5b26c5c70f888b9fc2f4654b9d665bbb5f265acf5b82a7729aad72b25b3b44ff796a2597757cfb4ef63f5ca387872de1b33a4b3d7be4d92f6ef5686bf16f0ac6b9179299e61f5aa4ccde5b4e4ee6cf8a355fb54b6712fdd40d29ff6b3c0ae534a83cdf12adc385fdc7cdf89ab534cd279d2fdef28040bed5068642969bbbbf1f80af62fecf0fea7c9e1b0eab66ae1d22749752ab7dedb59edb5bb52c9289466ab090e4d796d9f6f4e9f2a257512c651ab80d52c1b4dbc68995b6fde4fa5778b2d6778874b1a85b79a83f7b17cc2b7c3d4e591e6e6d83f6f46eb7471c9f377f9aa65350ec68fe6a991abd23e209768e38a027b7cb4bb47f08a5463410c48f744e1d372b2d6e69be23920c25c0665fef5642a8ff8153962e293499373b6b6d6219d43249569af4377ae062f32361b0b2d5b4bfba46dacf4b9510d9d9fdb035396e873cd724ba9cbf75d29d16ab22b0f95a830675be78c75a46b915ccff6bb7f106a06a12363eb408e90dd531efc2e7e6ac559276fe2a99202d8dd52d8d171efcbfcab516c92561b8d3a28062a6082b265a1228855844a444a917e5a819344a6ac255646a995ea40b4952b3ae02b3edddd2aaa38dc2ba4f0d78ae1d091a27b7b797cd6fbce07cb5ad1f8cc6ba4e1668e66ef55b3b57dad26e6feead409aed9e7f896bdaf4f9bc3bae42525d32cdb78f9d7c95aabac7c28f0bea701f2b4f5b563c892dc942b5dce32e872d0960be1ad16792ff68da32166996a0fed8b3ddf2bb6eadaf127c25d5b48579b4b99751b7033b318940af372d224d2eeddb94ed21b8db8ed5cf3ab520eccfa6c164b9762a37a72b9da25e5ab61bccaba96b04ea365d455e7f25c98d76a9a96d3549a38f6ac8ccb593c4ccf4d70a612da1ddae8c8c771beb56f419a73e8d7a870b0ac9fee3035c5da6b22040cc599eb42c3c4f77f6a0892b46b53f5b9a30adc2545af70d89ade6b6ff5b03c3fef2d45b837f76b5ffe1362a8a842ced8e94e5d62d6f326e2c2dd3fe02335a2c6f7478b5385ea2d8c463ed59f76855bcd5936aaf6aeaa3d26c751cfd92e7c97fee373556ebc357a99c88245ff0065aba218a84ba9e456ca2bd27cb6b9cc5aa19cf9bbdb6e7a5688db1fe552ff00674d6d14afe43c714442b9dbc29355cb8f5ae84d357479b3a6e0ed243ddb8e8b516e4feed31ae02ad5796ec7f053332cbc8abf2d43e56e7dcd4c46565dec7e6a95a41d6980ee17e564a3fda5a634bbb34c2f401213eb4cdebb69865dd4dde2801f93e948c4547bff00ba69165dd8e68025ff006be56a6b30a8cb8a679c173f3d0049bc2fdd34d79867fbd5079858548985a005d9b8eefd2a4e3856150bb8c1665a42e770e680256236ee5fc16919fe5f98543e69e690cdb5280253b5a8dcca372eda87cc1cd35a4fef7dda009b70f9777cad48cc735179bfed5235c2a90bed4012b11e9488c30dcedaaff691fc25694e3ef31a00937eef97f8569085ddb987caa38a6ee565a8f7fcc39f968027da3f8691e4e471f77fbd50bb7cdbbeef56a4de572caebbb1c55012b386f31451bb72e1bf84541bf6e377de6a0c815be5dbbb1ba80277719db8a6dbc85542fcacbfef5557bc1fc5f3372d522caac8adf2fcdf35032696e4ab7ca8d9ef45553759f9a3ef45481d16053aa15b88ff00e7a2b53bce8b69fde250644a578150bc239e687b98971ba64feeeddd49f6a857ef4c8d401190568c0dbd697ce86463fbc4db51caf0ff0004c9ff007d5004b918a7ae2a97da22ff009e8b4ad344bff2d97fefaa00bdbbfba69dc6edd54d2e63ff009e8bd3fbd4f4b88d47fac5f97fdaa00b39f97e6a56aaff00698bfe7a2fcbfed50b346bff002d17fefaa00b34aa4555fb541ff3d23a54b98db3f3a7fdf54016b85a6ed1f7aa2f3a2ff9e8bff7d539648d87cb22fcbfed5003966fe16a99185556d927cdbd6a32cb1bee59159690cd1dd4b9dcdb6aa24d149f30916a5df1b10be62d022c2b6da72b55659173b7cc5a7f98acbb7cca06590697705aafe6c7ff003d169de645c7ef168026cd06256a679b1ffcf4a4dcbc7cebb680047f2db6b559561559d6261f7d6a312888ed693e5a00bfc63e5a55a804b132ff00ac56a559236fbb22d0058e3ef52ae3eed41be3ff009e8b4f12c5b7fd72b5004b81ced34a405a8f7c3ff3d168df167fd62d03255fbd4eda36eda8bcc8bfe7aad1ba1ddf348b40c14f94fb7f87356571555d637fbb252c32c7f75e45dd4865bc8c52ad4598bfbeb52a6d6ef40d14b54d3a3bc8bfbaebd0ff00435ce4d1c96ce5251b596bb2f2873cd646b515bc909dceab2afcc95e56330cadcf13ef78673d9a6b095b55d19cf33d19e6a179a35fe35a12656e855abcd48fd19c6c8aedfeaee376ef99b6eea7e9ea3ec916c1b782d55e593c8b3938ddc96156ed06cb78d73f75057ad8bd29c628f8ae1b5cf8caf57fadc981a7d467fbc2856af30fb568731ff7b753e294a9a8c0a40bb69a21a460f8834a16b706e221fba97ff1d358f8f2abb7fddca8d14c3744fd56b9dd4f486b193e5f9a06f991ebd1a1554972b3e2f38cb1d293ad4d7baf733d09ff008154ab513a15a1651c7de56ae83e7593fdea915aa1c8a7825bef7fdf548964e30c6ac8f997fbcd8aa88df375ab08e3750432758f754a210d8e2a2864e957528666c6ac2b53430aafcb8a72aeda955866a5b10f440ab532d401b753fcca86058ff7a9e085aafe6d2ac950ca45a57a766aa89a9e1e90cb41c54cafb6aa870b434d5361969e70a2b8cf1aeb7359bdb3c1232b64e456fdcdc706b80f1b4c65789f3f7495adf0f1bcd18576d41b4775e09f8b5f63648aee4fbc76bd7baf83fc7f6fad59e1e4565fef57c4cae6bb8f00f8ce6f0f5dc4bf6b956ddd879e9db15e972a3c992e667d7ef7317de575f9ab8ff19f80f4ff00144525c5ba4569a96389957893d9eb3ac35f12ec68a4dd130dc2b693c436b6d96b89e28f8fe261584f964ad23b309f58a1514e8dee7836b3a4de695752d96a103453c47f06f71ea2b2c6e8dcfdedb5edde25d4bc0dad60ea71c979322615a0ca951e99ae4ef57c1db76da6813b71b774b726bce9c22b667e8f81cd6a558479e94afd74d3f33cfd88a1776432d74535859bc9b85aaa2fa5115ac317dd8d16b95b47ba9e8655b5ccb13aca37330ab936a77b329db1bc7ed5795429f942ff00c068c9a863d1bd84d0350b982e87985d777435bd6b74ff006e8fce93765b9f9ab0949a91252b4d3b1cd570f1a8ee7a13cb67776ef0cde532e785ddfad72fa9e87716eecf12799128dc0ab676d662dded036d4f16a2ca46d76ade8d7707a1f3b8be1f8d68b4d99b365fb522c3b6a6bbf9666dbf758d562f2ad7b7177573f36af4dd2a9283e9a0fdabcd23543e63d234b27a533226fe2dd46e0ddaabbcb27f728f35b6f4a009436d26838dbd2a1131a4f30ff0d00499db9a6b2aedf986da81ee76d337b4bf31ddb68025797aaad3122db867ddf351bb6e78a5f37701400efbb4647a5319f6d303eeaa0266614c246da6336d62d8a6799ba8024e3d6863b8ed65a84b9a4f30367686a009171fc34d761fc437540d73fc3f7a857dcdb9a8026dff0031da2a364f33bb5279bb73ef4bb8b27e1cd002b32fdd51f2d1fbb55dac1b6e6a22e19be6f5a6ee2bf7be66c50058f346c1cd3376e52cf512b8f91a866da3fd9a0072b8dd5233aaf65a83773bb0bbaa2130c9dbb979a009c3fcc157f8bff1da43b558a7fc0b7540f3360aa37cdfdea5dc55f7619b7617140136c390ca7e6a6c69b176b7dccfdea4593ef6efbeb4dfde32ad03489e2445eea0e28a6ef8c37239c515233805d46f1bef4ef530d52eb69fdfbd676e3c353ce57bd683e545c9751ba6fbd3b7cbf37dea89afae3fe7b3ff00df55073b4d35b3914072a2c9d42e3695f3dffefaa72ea170c7734ef55369e29fc70cc680b169f51b87fbd33520bcb8e3f7cff2d54dd4b9a02c5a5bfb85fbb34bff007d52adfdcee2be73d54fbd47f16da065e5d42e3f8a66a46d46e17fe5bbd54cd2336dcab50162d7db27e3f7ef48d7d3e7fd6bedaaedf74734c63f38a02c5e5d4aebfe7bb548baa5dc6876dc3550c53598ff00df5482c5e7d5ef95837da1e9edabde32ff00af6ace3f330a787db40ec5e1a9dd2ffcb77a3fb56e98a9fb44bf2d52a543fc3414922faeab78bf2fda1ea45d56f303fd29ea822f3b5aa6f28eda468a08b4355bce7fd21dbfe054f5d4ef77ff00c7c3d57f24aafcc3fd9a36505fb35d89d755bcfbde7bfcb47f6b5f7fcfccb5079746c140fd9a2d7f6cdee7e5b9969afacdeb3eef3ddaabc89d6902501c88b0baddf2ff00cb77a06b1a82e7f7eebbaaae37629db77501c88b1fdb37cbff002f12f4a06b57dfc370fb6ab6c3b69a63fef502e445cfedbbec6dfb53b6da6ff6cdf7fcfd4b55b67cbba8f2f6d01ecd16575bbd57ddf6a7dd520d6f50fe2ba7acf641bbf1a551fc2c3e5a07ecd1a1fdb7a87f15d3d3ff00b66fb77fc7c3d500bf2f4a9234dc681aa6bb1a1fdb3a8e06dba96b73c2b7de20d5758b7b4b3f3ee652dbbcb45cf1ea7daacf807e1fddf8dafcc40b41690e3ed173b784f61ead5ef163a6e89e0ed364d3b428161761f3c9d5ddbd58d6356b460bde3a29611ce492470dadea29a2cff669b6b5c0019d236ceccf635c6dfea2f79765ca6d561b6a5d5a0b886fe74b8dde6b3962dfdecf7aabb032957af22ad773d0fd3f29c8309858c6ac55e5dcad3d8f9bf32d3ace15b38a6f347deab2b95ff6968b975f224fe16dbc56308a6d1ee626a72d2937d8ab733c2d61f2fcbf2960bf5ab11cc1405f9578154e7897ec6abfc5955fccd69c91c6ac7714aedc7fd948f8ee10ff0097b27dc60997d569fb82fdda8c883fbe951fda214fe35af34fb5d1963753b8aa9f685c7caeb4dde7f85d6a912cb4d8db4ab32ed68a50b223750d54fed6db8b37dda67dae3cf5ab46338a92b3d865fe841419ad5d9a2feef75acfb7d0751bc85ae2183744a0b6fdde95af05cc8a7f72ccdb6b62dae6eece54787eced14ab90fdb3dc32f622baa9d576d4f96c7e49072e7a5a5fa1c1336d27fd9a7ab568f8d2ce18af16feca1f2565ff5e8adfbbddeab5876f76bfc5f7abaa2b995d1f2989a53a13e499a0b26da9d65f7aa68fb854caa28b1cee45a590eeab904ff002fcc6b351854892b2d211b0b30a7f9df2d6646e6a6898d4b117964a5f33deaaa9fef53f77cb5232cacad5207aabe6fcb479b52517165a910fbd5147dcd5379db71458572db4c29ad25541375e6ae69de47cd35d9fdd2f5f9a958704e4d4519b7d3955db9ae5756b0bbd47315bc0f2337f0aad7a54f65a3cf0cad0edb9959860eec041d4d6345a9c3b76c31a46b4e351c1dd1ed6172396235a8ec8e32c3e1fea52b7fa518a05ff69b256ba3b0f036976d8fb43cb72ff90ad6fb4b31f98d48ae294f15525d4f730d90e128ebcb7f52f43318215862765445da17da959f77deaae92d3b3f30ae56dbdcf56186a70f86287b7dda6b2ed14d571433fa6ddb52cdec0d47fe834e56a8ddc2d4b1a169314c6982d56b9d4a0b55df2c8aab4cadb565aceda33fc5552db52b6be52d0c8b26d353ab54b2959aba25de69c9f330a88311527dd8cb7f1374aba507292470e6189585c3caabe82dc4db98b543e68a899e99bbad7bf156563f18ad27526e6fab25dfd775279bb71f37dda837eda636194f34ccac582f4ddfd7f86a1edd5aa27903669858b0f27bd45e69662ab506d3ead4a57fbb401326377cdf7a8328a87715148c4fad0225966dbf7aaab6a8395d8dbbd69c73b4ee3bb9a8f6865a063fed571229758d996ab43a934b71e4f92df5a9b7edf95775270bf35501677f4dd51b3ee5f97d6abbbff0e7e6a4c36df98d004ef37f77e6a62bee3518c47471fc5fc3400f5c2d22bff1547b82e29ac43e571401233954f94fcd4ab27ca15bf1a81b3fc2697f84fde56c7f0d00485be5dcbfc5417a8b78ddf29a8db3203b7e5a009f798d8afcdba95e43b176ff0017cbf35554ced3cb7cdff8ee29de6865299dbb68025c9dff00ddddf2fe142aac7d99ba73519fb9f37fbb423fc879fad004cbb9bfdaa4dff3ee5f95aa02ecafb7f8b14762cd2503275957eeb6ddcc680e1b2e817e514cc18d4b28565c53166f9f087b71f8d48136f2ad90ad8228a89189ce377e78a2828f3f5a7ff0d44bf4a977ee06b6006feead14d1860686a5600a5dc7eed229e94330a602eef9b6d3ea2ef4e1f2d001cfeb4e2db8d2229a4c1c9a901db851c33fcb471d7348df2f6a062b53194e6979e169deb400aadbbe5a1806f9a85fb9f8d1b7e5a0635b0b4e55dcd49dea541fc59a0690806da9614ddfe14b0c0d2baaa8f998f15e9de11f015bda88efb5e8fcc6fbc967fd5eb0ad5e3495d9e86070153152b436ee72be17f066a7e269c258dacaebde4db88d3ea4d7a7e91f02e08944bab6a6cc57e6f26d5703f1635d5c1aec56d0086da048917a220002d741a65dbdcc397af1eae3e72f8743db796fb08dda3cd2ff00e1468cf3f92b77730331e0b6196b27c2ff00076ef5f9ee85f5e47a62c6e54204f319b15e99aee16e863d37541a3c9247752dc13b89614a963671d25a9d73c153a94b9d2b1c2eb5f00f5ab34dda75c5bea8bfdd1fba7fd6b92b9f869e2ab79363f87f52ff0080c5bff957d2da7eaa92aedddf32d684f7b018487629ef5e946bf32ba3c39d29465cb247cb29f0c7c572e366817dce7ef263a7d6a51f09bc62df30f0f5dffdf495f40dc5d9425bed0ce3fd96aae35b65fbb706a1e2ec74ac04a4af13c06e3e16f8b2dc8f33c3d7fb98e3e54cff002accbcf0beada63edbbd3af22dbff3d206afa563f11c99f96e48ab49e29b85e1e3575f5a6b18889602a2fb27c9cf16df918eddbdaa2fb31dc6bebc88681afa08af74cb291ffbb244b59b77f0dfc28e19e1d1ed73e9b6b5fac2b5d182a3152e59a68f95bc96fe114c6465f9b1b6be88bdf0678522e6e745580370644ce2b0eefe17f84efc16b3bfb8b42dfed647eb592c6c6f6675ff0067b6af1fc8f0dd878da3e5cd3d622cdb7ef57a66adf06355b6432d84f6fa80eca1bcb7ae26e749b8d3e7686eedde0953aa48bb4d7442bc25b330fa9cef6466245b982ad755e0bf05df78af5016f6c8638a2c1b89d97e48c56b7823e1a6a1e2965b8c7d934fcfcd70ff00c5eca2bdaf4dd32c3c33a647a6e990ed893a9eeedead59d7c4282d029e1da959ee36c2c6dbc3fa441a469e3cb8611f8b9ee4fb9a82f1248903f0d9ed56f7bb1cd35e1f37ad785526e6eecf5694553390d7b4a8f568f714d932f435c3dcdb4969318a55daca6bd726d2cc83e57ae7f5ef0acb791ef4dbe6af4353176d19f4b96e691a6f924f43cff6d327dbe51ddea2a6b9826b599a295194ad55b8c3285ceddd5d3423cd5123d7cdab2860ea4fc8a570a653042bbb6bbaff00c0b157651f396c55384897528d57e6550cc3f015a5b371ae8c73bc923c4e11a7cb8694fbb29336dfe15a81a6dadf715ab4da11b4ee1559ed87a5709f59733cccad95645a6a3c7fc49dea792db6fddaaaf115aa4432e2242ebd3ef54cc8ac776c5acd472956629cff00135324b4179f969766d3d688e60cb536372d31093a2ea162f6931dbb870d5c3de69d7ba3b32cb1fcadd24ecd5db6d3c3523b2cb198a50ac8dfc2d5d142bb83b33c6cd727a78d57da48e3aca62d18fbdf30e9fddad28db728e69baa689259eeb8b22cd130e53bad65c3702265d9bfa6dfbd9af4572cd7344fcfb1584ad859f25546e853c2d4ab54ed2e44ab57a323158b4d1cf7248f2b53a546952ad40ee3e947dda4a4dc280b8fdf42b6ea8ea4076ad2b05c919c2e2a3339a8e47accbcd46383e563b9a9a8dc4e42eb1ac9b4411215f35cf154bcfbbbb45865795958fdd5a86cf4ab8d6642d74acb16797ae85238f4f40b17ccdf777b75ad5ce14d5ba9e960329af8a6a7f0c4b314bfd9fa5456bff2dd86e7db59897263a63cad966dfbbfdeaadf692a3e60b5c4f567df538aa71505d0d886feaca5e6dae716ef6f66a91352fe1656a9713453474f15e7f166a4fb596ac186ed70198eda57d4638ceddf51c8cbba3716ef6b7cd449a8471a86675ae66e7519d986cf956ab477922c8771dcb4fd9873a3a57d7b6fdc159d36b17ac7f876d578dd67fba6a75414fd9a1a90d5bfba9feec9b77562f88fce8ae2057919959770ae805b0cee6f96b0fc59b7ccb4647ddb41535be1a2954479b9cc9fd52563a0f0dc51c7646554f9d8ed26b62160c76d63783af205b19125755f9830ddef5d2450c127ceae8cabdd5ab2c4c3f78cd729ad7c1c06a29ddd2a0bc98ef08a7eed1757eab98a2fc5ab39ae37676b5746168f2be667c8713e6b1adfecd4fa6e4cd216cd35a6aade751e70af411f14d167cda89ae2a069ea3597e6a0562c79d23522b541f680a0ed34826db56162c348698f2956a8bcf34c69bfbb405895a66a5f3fdeab3cd4d5987dec502b165a5a469829aadf68a664d03b13bdc1e76fcd4ddeecdd699b955775209571ba80b13ab8a379dc6ab799ba859be51b68d0562767f7a69936f6a85a5db51f9fb4166a02c58670cdb96867e76ad55fb47b3531a66fe22dd78a0562df99b40fa544ef2c83efeda8f7d1f69e3afcad40589b732fde2bb68df263692bbb3fa545bf6aeec32eda15c728bfc54013339697e6ff00bebb50bf27cca373d566b8d8db9c2ed6f9697e5660ea5bde80265943613f857a6da5c85aae1f6ff07d69dbc64f0bf2fcd4013a344af2eef9598eda55902af446663fdefbb5017dd96a623fc859df6eeff67b5481684bff0002e78ff6697017e5c2f5a857ee0e3735009e5968289d1c31c0db8028a88c46439c67de8a4070a98dd4fed483b51eb5bd8055229ad9dc69c3e55a6163b68017eed2fc94dc538a85cd030a3348b4ef9996800f4db464e7ad250d8dd400fda18d0a3934d506951b6ffc06a4056f9be5a10eea4c8a7ad030fbb9a55c5273c2fcb4f1f37de141690df5e2a58977295a509fc38ad9f0ee8736b5a9c16510f99cf2fd917b9a526a2aecde8509559a844e9fc19a043636c35bd423e33b6da26fe223ab574675b91e4fb9506b0eab722de1f960854451aff754564dc6e51cbed5af9ac4567527767ebd94e554f0f878c7a9d75a5e2ce3727deee2ba4d0b5936d2ac47730635e67a66aa96b3857999b77cb5d7da4ff30e6b0231f834d38b3b5d7238db64b9fbc2a2b08b65b67f88d5a445d46c2dce3d05599ad9546d03680299f28aaf2c7d9b31e69a481b729db5660f1198d44538ddc726aa5f8db5952fdeab8cdc763b23878558fbc8d5d42e61970f095ace698fde5aadbbaeda750e773ae9d050562456f7a9e09994820d53ddcd4d136deb5372e70563522ba2bf36ce6ba1d33588ee94432bec987dd2ddeb958d95aa6da1856b0aae2ee8f2f11858d4567b9a9e2bb69e2b73770e423fc93c7dbd8d717f62476dcaef1376dbd2bb1b3f104f6d17d9ee62171091821fae2b46d2df43bac49670a2cbfdd7ea2aa494dde2cce862a7848384e3f347116ba4f88a03e6d949e6ab7f78edae96c748bad476ff006d47a7cc89cfdc0e7f335a72db95cb48e55076a634e650117e441d0509a81957c5cebec97ad8735c88e3105ac691429f280ab8a8021ab31441aa7fb1d6726e4eece6e68c34450e39a72938f96ad3daeda818aa5458a5352d813eef352148f1f3547e72b53598bd3159b6713e3dd212561770a738c35701326e9071f32d7b45f5b2cd0b24bb7045790eb6d0db5cdea27cc9bca67e87b576e055e67a18bc73797ba0cc8b35ff004c9df3bb6285fcf9ad2871bab3b4e50b0cb2afdd95ce3e82ae42ff0036ec54e2e5cd519f4b90d2f678282efa96d978a8de1a7a38a56f9ab98f635294b18fe11baaacb156932540e95484d99ad00fbd8a88c3b5ab40c63eed412c5b69937218f72b55c8242b8e2aaeda911ca530b9732186e5a63ad10cc3956a9131fc340ae4713796d5cfeb7a2796ad7764372ffcb44feed746f16da89498cff0edee2b5a555c1dd1e766180a78ba7c92dfa3385b79cc7f7a475e6b7ad2f1656dabbb762a3f12689e47fc4c2d47cbff002d117f84fad63d8ea12db49bbcc555c7de65fbb5eaa71ab1ba3f35c661aa612aba733ae8d4b0a9d54e3a51a7b0961899ca79bb790ad5a221ae67a3b182651f29a8f23deaf300b4c750a4521dcafb0462a294edc5497127f76b1353d496249114fef557eed38a6dd909bb0ebfbf3136c41ba56a874cd20ea0df68bd475a6e8da68d4dd6ee57976a8da7fdaae91fe5f957eed2ab5143dd89f4593653edbf7f597bbd1772295d628c227dd518159d34be61a9a762c6a058b73572dd9f691828ab2d110f96d2f6f96956d770f9855a5152aaf145c2c8a0d60293fb37deb4d61a7fd9c3668e60e5325ace44a8e588b7cae2b5e4b63eb55e6b4979f91a8b956321f747f2ff000d44995cb3568cd6e594aec656aaaf6b2fddc5529226cc486e1a36dd9ab87520a8360f9aab269d267e6ab89a6f4a3990d5c81ae669fef3fe0b59fad45fe8caf8fbac2b756c36552d52d7ccb3997f8946ead294d292672e3e9fb4c3ce3e445e1acc8b244dfc438fc2ba38eceb98f09cc56ed7fda35de08ea71ba4ee7270d5652c33876653583f87147f65cb2ffa90d237a569c36e24ae9742b18e162e3e6359431138ec56699760ea45ca50d7c8f37be8a6b372b342f1b7fb4b54d66dc7ad7b3dfe9b6f7b098e7b759148fbacb915e7de25f02b401aeb4adcc83e6783a94fa576d1c6293e591f1189c96cb9a8bbf91cc79caa295e41eb59cdba3f969bcae5775771e2ba2d3b3dcd1330514c330aa393472bfdeaa27d9175ae0547f685621b3b6aa316fe1a3c9936d03f64cb4f38a4f34646e355d619171c353d606ddbb6d2b87b07d89fce8d7bd066ff00be734d86ce79cec48d99bfd95cd690f07ebd242658b4abd65e58feebb52724b729616725a2337cf8d9be634826fe15a8668e481ca4a8cae87695e8548a89df81c5333749a7668b2d371d569be6fcbbbdaab2b9ff0075699bf6e6a88712df9eef4c67e7aeda87cd1fdd5a469a35cd04b44fbcb215a11c63e675fad41f685a5f3429e9489b16376e5dcbf8ad34b2b306a89651caff00749a898fcc557f8a98996ccccadd3b7fdf229126dd2fcdf2b2d564946ddcdb556938dc3caf9b68fef7340ac58dff00307c2b7f1166a5f33731e76ee1c3545bf809fc542cad2fcbfc38a064e186d0db1775282ad2fcbeff003542893be368556c70b5622b76570ac76d2001205cf3b79a45f338da8cdb8edf9bd2a785155870cbfed54cdf7cee1ba801a90edf95ff008ead2dbab2eefbacdf37e1516e8e41b587cadd569d1332a955fe1a90274032589d9dbd28a8a505cf05968a4079ea28db4a71483e5a76777cb8ae80061c5336ff00b34ee776da6eddb48077e14acdf31a4db48d8a0637775a913fbd51b7cc4f14e57a063b68f5f969ac0b36da5ddd29766df954d002af4a1b14e0bf2d34a7bd05028a72a96a00a9110ae6a46902a8dc3ff42a9510b6688a266cf15bda1f86351d6a658ad2ddd9b8c965c227b935329a8abc8eaa342551f2c519b6f6667c228dd5eb7e0cf0ea683a2b5c4a556fef00cfac49e9573c3bf0fed745025982dcdc767dbc2fd2ba3974d3b7f86bc5c6637da7bb0d8fabcb7010c3b539bd4e7869d6bbcb91bda99369b692c651e35ad89ac597b5557b565af33547d44710debcc79feaba5369d7386f991ba3d6df86f52fb4c7e4b7df8bff001e15adaa69ad796c63755ddd8f7535c9daacda3ea8ab30d9d8fd0d6abde47a51a8abd3b3dcf63f085c348ad0b1dc2b7ae57a9ae4bc08fba59bd768c575b79bb6d0d1f0d8f872629a473ba97cc2b1e5cae6b63506ac591a83d4c2fc233eef7a7ab8618c546dd29abf2e683b2d72419cfcd5227ccb5106f9454e83a3504c87a6e5c5588e73bb6b54611a9fc7a549cf2b31cee2ae595becdb3cfb947554ee6a3821488091c73d91aaca16964cb65a9d8e3ab2bae55b177cc6b83b99bbf02a6036d45128e2ad2a06a7a9e7cda44b0aed5a983b2e2a38d4ad3da455f988e2a8e496ac8a7e9f31aabb47dec53e7b9dc7e5a8c3d4b66f08b4889bad058aaf5a79cb3522c2f526d75d4a97f3fd9ace7b87fbb1217fcabc4b5399995ddb6ee625cd7ae78ddfecde1bbb62fe5eec26efa9af2244fb55dc10e76f9ae883f135e9e0928c5c8c2bfbee305d59b13787e7b1d3ed4aa3731063f53cd672294ed5e9f70898f2ff0085401f9570fad98def59211f2f7dbdeb86726e5767dce5d89728aa76d8cd5719a7abd6b5bf8737dbabbb32b9aad3e8d2c4dd6a6ccef55e12764ca9cd359462a536d2a1a8d815aa4539104b10a8a542b8ab3b4f151b286cd511729b25316adb4750ece698b988d4ff007aa78e5dbf3545ceea519a02e5e49437dea79895bb55447a9d26db41371aaa1775bca3723afe95c2ebda57f655f145dde53fcd1b7b577b33270df7b9acff0015587daf466751b9e13babab0b579256e8cf0b3cc0ac450725f1475395d07528ecee834d1b371fbbdbebef5dcda5dadd5ba4ca1977766af30dbdebaff0feab79a8637ed68106d2d5e8d6a775cc8fce29cecec748cfb5aabc8f43bf1fecd57965080b31daabf316ae63a0afa85c9b6b57953ef2035ccf992ea57ebe532b6fc29db52ebfa88de1a193cc571b7e56fbb8ad1f04e9caf732dc30f9621c7d4d6cad0839335c150fac622348de86dd6d604b541f70524d95cd5dfef330fbc6a8dccbb98d794db6eecfd3e9c5422a31e85391771148a9b987f153c0e4ee1532a0a0ab91a4553c70f1f353e34dbf7aa70bc7cb400d48c53da2f9a9c9f2b53929143366eed4aa95232d1f7680b917931ab1e169bf648f8e16a55feeb5387f77140159ad1189f9297ec6abf72a7fbad49feed032bbc7f29e6a84d6c1d5971f7815ad43f7aaa941f695fad09d8992bab1c7e94a60ba29fc487f506bd21183286c7de15c24b6c2d35cba89b6fcce593e8dcd763a7cde65ac2d9fe10a6baf19ef42323e7721fdde22ad16695b37cc2ba8d31f6a8ae52170a6b5ad6f1a31b56bcf4f43dcc6527356476f6b346eb83e955af6cc72e9f29acbb4bc390e4d6bc3a940c9b643ba99f393a53a72ba38ed6fc1963ad4bbe2ff0046ba63cb22e43fd45737ff000ab35ffb51896da364ed36f015abd2e72be72c90020839153c9757b2affacdb5bd3c4ca2ad730af868556a5647029f076ef1ba6d4ad62e3fba4d6ad97c21d21107daefae266efb3082ba510c8c479a59aa64b76c7f1553c64d987d4a9c4e7a4f859e18d9ff001f176adff5d01a923f027862d902fd965b96c7de965ae8426ded514ca3f8454bc4cdf52e1868266747e0ff000b6777f6241f99357a0f0b78733f2e8b67ff007ee9f0617e66f5ab8b3fcbc2eda15693d5b09d18a768a25b6b7b2d3d76dbdadbc0bfeca014cbcd40b2144354ae5d98d24301948a9751b2a14231f7a4645f784744d7ee5a7d4217fb4b29dac8fb7763d6bcd7c43e0916be6be9e5a654ce616fbff857a95fc9b75fb1854fcb1c7248d5c6eaba808aea4d85be52715a42bce0f4676d1cb69e253535bafbb73cae4f94eda8f7ee535b5e2ab68e2bc175126d4b8f9b0bd15bbd73ff00c46bd9a73528a923e2b1f84961ab4a8be84bbf82d4cf3371e95139da36d26e18f96ace0689776d5eb4bbf6e3696a878fe2a38e79dd413626dfbb34aff2f65dd8fe1a886770dbe9532465bbfcca4d02682372c036688b76f62a7fc69c10ae1b3dea612aff00106db489b0cf24a95dc7e66ebdaae5b22a15c06dd8a8e36579844db7e6352bcaca7f8b77dddd408b2ddb685dd4d669547f77d1aa48f1e9f3e47cb44e7ccdcb9fbadbaa4045cca9f37cadfde5e28427785ceef969b0c8570d865a9506d5ff00d9b6e2801de59917afcd522e57e5c2fcc69a8bf7bf879dd4bbcfa2ad202489c282e4e39c51516d9371a280383db41f9695bfd9a369e2b7019ba85cb52b2f3f350adf36ea0076efe1c546df2ad4acc6a3dbba8189be8a5db42fcaa6818b8db4eee3f8a843b7e5a7d0343b8a615dae5a9ffc2cd4f584b6282d2044671f2d4f1425b15a5a368573aade25a5bc6cd2bd7a9785fe1f5be90865be115dcef8f936e51306b96be263496a7a782cbaa5777d91cb784be1e4fab325cddee82c0fcd9ef2fd2bd634db4b3d3204b6b48163893a2253961919fe515720b5997ef0dab5e1d6af3aaf53ea6961e9e1e16889e7f4f91a89e5675f96ae8b62e7023e69cfa7cdb7a2ad63662f6b04cc39967e379aacf20fe2f99ab71f4db83c93b96a84da7b72db2958eca55e0ca0c15c75ac3f11e8c351b5de8bfbe8fa7b8adf7b72ad504a48ceea68eea351c64a51645f0c6fccb73246ff007b66d3f515e9532f991b7d2bcaf4509a678b6de64f963bbca11e87ad7aa42de6446b4b2678f9dc57b755175472ba929de6b19f3935d16aebb643815cf4cdcf4acec7660e57810b520342d0b41dc48055c8005f96a08d6ac7fba6958c2a3be84837310006dcdc559212d9f1912cddcf64a8e3fdd26f63db8a8e24dcf4ce46b9bd0bc859fad5fb6877557b48ab462f95ba5070579db441b36fcad5227ca454aca1fb547828714ec71f373128c83f29a648ecc31b69e06e152f9429995d27a998c8ccd5325b9f4ad18a31fc216a658c50a012c47433921db4e68aafbc6b504d246a319a7ca42aae4cf3ff008a5395d2edadbfe7acb9fae0579e68108baf11d8263eec8653f80aebbe27de19752b5b553fea90cb5cdf8221f3f5b9e56f9bc983f5635e8d25c941b3aa8479abc5763b5d4ae8416d33e79c5723a6406f750504fca5ab73c4b288ad4267ef1a83c1d6be7de33fa0af36d767d8506a95094ce99ecfe51b474159f7761bba8ae8fc9f969a6c1a5078ad0f1e9e2f95eace2ae74d1e959cf61b73b857a09d04c9d9aaa5f6822242d8a2c7a14b348df95b3cfa6b42ab555d3fbd5d2dfdb04056b0e6414ac7a4aadd5ca0cbc542e9575a2f9b761698f19ddb714c7ed0a4c9f2d33695ab2f115a8997776aa0e70dbfdd2d4b9f9a9bb4e69eabbb140738fe7c96653b5b1c355f8e25b9b59616f9bcd42a6ab0c345b5aa4d21f6c6a9f7b67cb9fa508ce6d34d33cc658da299e161f32315ab1a6cc56ed62499a257eaddaa7f135b1b5d7aebfbacdb87e354e3dcc06cff00f66bde85a514cfc97191746bca1d99dc47307886d7ddb46ddd55352bf5b38774a9e623654fa7e35cf47a8dd59e22864fbdf37ad13cd75a8da149a6efc8db8acd50b325e2558a72c1224a5993f74e4ecaeffc2f6df63d095f1f34c4b570856489522ceeda38af49b7416da3dbaaff000c7b8d658e768a47d170bd352ad2a8fa22397e58c6daa13658f4ab2edb80a8c47bb35e59f77722443cd481368e94f48c548a85680b82254b80bf7a902eda7aa501cc26eff6a8e69db3da868cd21f3065a9149cfcd4aa0d1b3de81f30ab8a50dfc34ddb4503b8edbba861cf5a518c52ff00b540ee44c0d5774ff481c6de455f44e3e6a82e623f794503b9cdf8aa1316b10dc7fcf58c7e6b5b1a34c3ec8573f70ff3aa3e2b432d8c371fc509fd1a9ba0c864da8bf32b653f1aedb7b4c3dbb1f34e5f56cd549ed237e3937115a76a92c846c06a3d3f4c694fcc9b6badd2b44dc5536b7d4579a91f458cc5d3a6882c2cdd97e7dcd5b9069e5d42fddad4b4d3551403174ad04b68d7f868b1f2589cc399e865c7a1ff0079c2d5e874d822e33baae30dab4c44db9db5563ce962272dd8d5b783fe79ad43379310e52a59be5cd65cf26ef949a074a2e4f5624f731745aa324bfc5493615b72d45b8d26cf529d3490f4936b671f2d4a642d55da9f1e71416d2dc976fb55b861da9baabc4a5b15a9b02c38aa472d69dac8f3ad6b52f2f5fba941f9561f2eb86b9ba6b9b82f57fc637edfdb3716f175573bcd6659e5fe474dd5563ebf0b4d4211b764497fa78d57489917fd6c20cc9fed63b5708e0d7a5c16ed015768db631feef0c2b8dd634cfecfd526b750cc99dc8dec7a57a5829e9cacf94e28c1a6e3888fa330da9aaa24278ab12c5fbddaa1bad0542b7cbf35779f152891aa0fe2a15369e95232f149b7cc61419b4089d36a7cabfc34f117987765979a6ed1f771f353c3ff0017f7a8249581d9b73429dd86dbda9bb846fb9b6b549f78fc8568112872b28e697785caf99b79fe2a8f7edf954ad447fd2a5655f97a5224b82ef71da9fc38fad59da1fe66fe1aca920daa5be6564ab16d72de6b3306f946dddda824d0554663c6e5cff153e16dd9661b958fddddf76a188fcbfef5386157e63f37765fe1a902612f556fe1e949bc48ff002ff0ff00b348a855c3fcb46c3bcb306f634012eddc8093ff008f514f5046001da8a407012e376ea3271f28a73fcaa1aa3fe2eb5b8032f3b5a936fcb4ff00c7e6a4dcab9a02c0cbfc585a6d29cf1f351f77140c6ed2b8a71f9a9570a7e5a3eeaee5a060015c354918dd9a4452d56aded9a470aa9b99be50b41690c8a167c6daf42f87ff000e6f75f2b7770160d39be52f22e4cbebb055ff00077c3398aadeeb70343170c96dde5fafa0af51b594daed548d63441b5157a2815e7627196f7627d06072a6d7b4a9f22c695e17d1bc3d008aced123e06f6dbcb63d4d697970328fdd8a641709748437dfa89e5911f6d79726dbbb3d25192f749ce971e7729a97eccd12fcb4d86f3727cff2d5d5db228a564cce739af88af1394fbd52ef1b69c107a2d3d47b50a2632926ee445437cb51cb6eaf195a9cc4af48b09f5a39414ac625e6947194ac7b9b393cb2db1bdebb329b7ef5723e2bf108d33e4f957774f7a394f53055ea4e4a31399be81e2bbb1997fe59dc267e84e2bd3b4b98bc383d7a579aaeb306a707ce02ba90c0fd2bbed12e47414ac74e6b194a9ae65aa175884f5ae5e74dadf30aec3588d9a1256b97ba42bd6a5a31cbe7ee99aca69516a5c0a045baa4f5b9b4248fe5cd4e8bbba542b9fbb5a767a4cf2a6f54f2c7ab5091cb56a282bc994c8f7dd566da23bb7629c9a7c9e66d5f9ab6ecb49db8671472b392be26118ee436c19474abf182cbf30ab496c139f9686c2d69ca78f3adcef423d857fdda6354bb8377ed4c38a2c426c444356172d8a85178a9954fad16266c903e28f99ba1a29395a0cc8e447c1f9ab3ae06def5a1337cbd6b1afe728c401cd4b3ab0d172679378dee5ae7c497a17fe59284fd2ad7c3fb6f96fae31d5d631f80ac3f10dcfdab56bc7cfcbe71c7e75d5783316de1df35beeb48ef5e955f768247560d736264d742af89e6f32f044bf36c15d1781ad0ada34bb3a9ae42476d42fc951bb7b57aef87f4b16ba7c10aa7cdb726bcd4aeee7bb99d75430ea1d58b0c458edc56a4160368e2ad456c235e6927bc8ad579ad144f90a95e53768086d92242cd5cf6b6ead954abd36b1e6d635edc09735475e128cd4f9a4727a9c2d5cf4d16d735d5dfe3079ae72e47dea967d75197ba6760e693654c146e346299af3158c5baa17836ad68041b8531e0dd4073992c9b5a8453baaf4b6fed5122056140730f484b0a658068ee668b1f75f77e7576261558395bddbfdf5a05cc731f102d0457f6f363fd726dddeeb5c9acc632369f97bd7a17c40b6dfa3c170a3e689fafb1af3762776daf6b04f9a9a3f39e20a5c98b6fbea6814916e55bfba3767f0a9ede53b59fef2f7fc6aab4862b9b7973db69a724cab26df635d763c21cb99661b47de35ea53c5b6cc27f7502d797690a5f50b74fe26907f3af54d4f296edb7d3a57998fdd23edf8595a9ce4517017ef7f0d445b7549237cd4cd9fdd35e71f5bcc1183e9522a53a24dd56228fa501719143d2a558c549e56da76df97e5a41cc47e50dbd28c0a9314dd940f9888c5bb2698c95394f96931407315b6d1b454db69ad15052911a0dd5204dd404a9ade22dde82f989218b720dbe94d9edb72f4ad1b7b6da82a67b3dc0d48b9d1c7eab69e6da4917f0b82bfeed616833496ce531f329fc722bbbbcd3b742c98f9ab8829f66d60f0abbf0df37f0e7ad7760e5bc19e167b4af08d78ef13dafc3d656b2dac172e55bcd40c3f1aebad2186240b1c785ae0fc0776b2e99e56559ad9b6fe06ba637b328c29e2b8ea2e59347995b9ebfbd73730e691e58a2eff3562c77937f7da86b82df331a8ba30faabbd99a52dd990ed4a9e20ca9f3565d9b169066b65f1b284675a2a0f9514ae67ac8932d5a93a86aa9e5ab1db499d341a8a287947753fc8abeb08fe214f10afdea691b3ae65ac2697ca356ae0aabd400167a0b536d5c96da21bc71bab45ffd51a8acd071566e30b19aa48e3ab3bcec7cfbaac325e6b97cff00798dc37f3c5761e1af8797b7804d7a7ecf1765c658d52d134b8eff00c5d2c38fbb72ec7f039af5f50502814cfa0cc3309d08c69d3dda32ff00e11eb0fecf5b06b747840da03579ff008f7e1fedb34beb02ef25b677a752c95ea2d1c99eb4c931f75b6d542a38be64781ed6738b8c9dd3dcf94ef136ce19aa065ff80b57b2f8e7e16477dbb51d102472f25edbb37bad7925cda4913b23a6d65ebb970548af629568d45a1e16270d283f228b29a17b66a42863a6152adb73f4ad8e168172a9bbe5eb470cbb71f4a5646671cfcb436e6dbb4eda666d0bb43797b46ee7754aa46cdb9dabbb762a2fbdf77ef53a250afb586ee28244fbaa598d496df7f77cd4cda1b0ac69a8ca8dfecf65a4497e646d9f2ee65a214dafb71f352f9bba31b4fcea2a28243e697fbbb9a811755e4c85c2d397e5f976f6dc6a3450efb91dba54e18c9955dbed520099541b8b6efef353e32d8fde9daab4d1ba5efbb9dc3f0a72639562bb97fa502278ddd071d28a844811b03f7831d4d1480e1fef26ea6fe35270df2ad0c878ff0066ba1a0223f36168e73b734af4883750316929df771fc34ae9de900e4f953e6a5d87752a254f1c7c9a0a41142ccd5ebbf0e7e1b7c90eb1ac46dd9a0b575ebeef56fe187c33f2ad61d7f58b7dcc70f6703ffe8d615e95cab16635c189aefe189efe5b824bf793dc05a87eb4efeccde3e53cd2898ad5ab6ba1bbe615c1ca8f5e739c55d1496ca5b77ad15b70f0ee6153f9d1ca6a4551b76d4f2239aa5793dce5ee6e5a39d940f956a7b5d60fcaa7e615a3a9e9a93c45947cd8fe1ae61d7ecd36d63f2e6b269a67a347d9d78799d7d9dd8b853c6da9a5c9fbb583a7deaa1c13f2d6dc7289101ab479f5e8b8484c956a911b7535b14cfe3dd4ed632b5c4be6db11fa579a78e6d8dd471ec7f9a23b8d7a45e7cd11ae1b5e0be76c7fe24353247af95693387b298452ed6f518af4ed3ae0dbcab5e5572e20bcd8df2f35e996721d8bc7502a0f571d1528d8ec9244bbb6183dab9dd5acb69f907de1c8ab1697bb715a81adee94072b45ae7cf41cb0f3bf438c58255f97635392cae1bb57669a4c2c77022a64d3625fbdb69721d32cd22b64735a6d8ec218c5be5edbbf86b6d2c2e27c798df2fa55e55b5b4f9be5aa373ac73b62dbb6aac714eb4eb4af145d86d61b615234db7ee8ac1fb74b2679a916fdf8a644b0d36ef2359e63b7e5a81ddb9a8a2995be652b568e319a56667cbc8c8371a9a3cbe2a368cb74a96088af0d5366126ac498dab49e7b676e29ec0d46e36d3664acf71c66a619c2d412cc17eed42f36ea0d634ae2dddffca547cad58f7537576fe1e4d59b8905646ab318ac2ea5feec2edfa54a3d1a14d455cf1fbb3e7e6e19d776f3f2fe19aec22b83a778434fb75f9659d37edf62735c4bb8549599177306ae8a6b96ba307f0a45024407f7702bd4c52f71448c9ad2ab3933a5f00e8dfda9aa0761f243c9af599ef2dec96b8bf0414d334756f2ff007921dd9ab57372d2b9662ccc6b8546c8d31d19626bfbdf0a362e7c421fe541b6b1ae2f257cfcff007aa9bca7f8aa332ff7a834a383843644cd707f8aa092534c7977542f37149b3b614d152f0d63dc275e2b56e5c7ad5097e66348ec4ec8ce78faeda660d5a91298c828b0730d5518a31ba9d8a301680e623684366aacd6957b21568e1a9873142184edf9a99243e5de5bbfcddd7f3abe576d57bc665f2595b6fce2817395bc55179be18bbfe26450c3f0af266eb5ecfab43e7e8979130fbd03578bcbdabd5cbfe168f8de264b9e122c5e219ede3d87e64f9b6d47616cf1cbe6b9fe1ad18ffd42eefbd8a6f1ced455e38af48f9725d17647ac5a337fcf415ea1ab26eb59776ef95775794e96db75783febb2fea6bd73518bccb39557fba6bcacc3e247da70c4ff007325e665226e51c9a9238a8b443e4aeef4156553fbd5e71f51cc1143526ca7852bf2d2f2b9a03986edf969d46286c521f309b452329dc36d35a9cadba80e623c156f9a9571cd48cc68dabc29a039c85d47dea29e546d2d8a67fba290f9c455ab76dd6abaa9ab76a9b8d05739ad6d1061577ecd50da45b856bdbc5b94714e27256aae2cc3b8b339ae07c55606deebcdfbab9fe75eb573644af02b8bf19e9de6d96e08dbb071f5aba4f96699139aaf4654fb927c3cbddba8a44c5556e63d9f88af5016f171c6eaf0bf0edebdb4d6d7317fcb1757af78b6612a2ba9f948dc3f1ad71704a773e6e137c96ec35eda32a3f845509a00adb41f98d6d1883fcb4b1da46873f79ab95a2a188e5dca561607abfcb8abd32718515695453b6ae3069a89cd3aee52bb319edd9ffbd49f673fc22b564dab50f14b94d5566d155613e951ccc156adbb9c1da2b3ae89aab174ef27a9464cb9a7c715371d6acdb2fcc2a523ba6ed12e5a47b7e66a75dfcb19a9e153556fdf086aeda1c117cd3386f04587fc549aadc7f7256c7e26bbc92658b9635c7785dda2bcd5bfbcd375ad5babc94e46fdd4ba1e9e2e9caad6d7c8bb35f97f956ab14695f0d26e5acf1249256be9885be623754ee4ce9aa51ba278a0d8839ae4bc6fe01b1f11db3dddbc6b06a4a32922f025c767aed2688c9dfa7f76976875e95516e0ef1385c9497bc7ca97f65259dcbc32a6d74254afbd5420edfef57aefc58f07ff00cc72d13ee8c5c85fd1abc8e5f973c7fc0abdaa155548dcf131787f652b2d888a6e1b5a9caa683f2fdda5e1bef7dd6ad8e16277fe2e9c5382edc73ba9872adfed53c03c329a08159770dcd55a58db9e776d6fe2f7ab8807fbdeb4623dd9a0451b7b799653b1eb4ad936a065f959cf3519611e771ddfc5b6a6b663cb31a092cc7f2a8ffbe7d2a446e8aa376d1f7aa3889601b3b78a90659c2b05a421ecabbf72fdd3f31a77dec328dcbdc532342a8385f969f1e5946d140891011cab107d3b5140503e521b8a2a00e159be7a72f7a19aa42768ae902b36771a7e0e29e40d84d232ed4fe1e9400dda587fb34f54f76a4c1cff00756a545e940d0f823dddabd6be12fc37feda9a2d7353b7dda5c277448dd2e251fcd0562fc31f877378c7512f2a32e9b6f86b897ff69afb9afa4e1d3e6f25228634b6b78942471aaf0aa38005653bdac8ecc2c637e69104997ff5af50fd883fddad45d1ff0089b76efef5432584b1e768ae474bb9ecc310b68b3266b03ced6da6aa02f13e2515b45190fcd504d1238f985632a5d8ec857e9226b416ad18c75abab08ac58d4c0db96b5edaf23640adf2b54289cb5e2d3bc47bc43eed737af69c39744f9aba7607692b59ba8e7cbe953382b1584aae134d1c95a965f9586dda79ad7b5b964e73bbdaaa5c28cee5144195fbc2b151b1ec54b4d6a6e25d06c1f96a5cabaeeacc86455ed5662942fcd568f3e74ecf425b8ced35ca6af6e1ae791dabaa2fe67cad58baf43b91081ceec1a99c743ab053709d8f29f1459fd9ae83fbd77b6721686276fbccabc7e1595e2ad3c5ce98d2e3e68ab52c7e5b787fdc5fe558b47b7526a714cd38c9ab71bece6a9c3fed1ab2a6848f36a22d7dadd7e5ded41d464e7e76aaad4c6fbd4cc5518b2492e0b776a89a51e94d7a632fcc291bc6091324b4e57a8866955b6e39a04e25e865e455e86e7a0cd62897e5e29f15c15614184e87323a246e956d30d5cf5a5d37981b35bd6efbf14cf331149c09da3aaf36de79ab2c46cacfb970a4d0d18524db2bcc42e76d54727152cd255677a83d2a716915a4f9ab1bc5798bc397d8ddf32633f535b8b1167158bf1013c8f0a4edb776f9117157461cd346d56aa8c0f1ab97d90ac5ec3f535d4d8c1e6b448bf79885ae5ee7ac49b3e656450d5e83e14b0f3ef159beec4335e96316c6192cb96336767027d9e048d47dd50298cc6ac4882a1d95c0d1e8c5a7a95dc16aaefdeae3c551b426a6c6f192451de79a8257fef0ab9343b6a94e36f7a93752453b8766f96a93ca57bd5b96a848b5490390be66ea6efdd511ef4daab0b989f22999a6fde6a5ed4585cc3f686c52f1f756a3a72e168b0730e02a0d41034219bf85837e46a7ddbbeed457aa7ece78ddd28b0b98b1709e6594cadfc48ca7f2af10d85a629fde3b457b9a2192dd97fbcb5e257e862b9997fb8edfa1af4b01bb47ccf11eb08309a69d93f731fcb17ca6989793affad4ddeabde9de72c9f3a49f7b1be2fef5584b98bca117d95559496cd7a67c90cb62be7c32fde5dc33f81af67993cdb7ff00794d78a4720f955477e4d7b5da9f334b81bfbd18af33305b33eb386e76538fa19ba5aeeb68b8ed5731ed50e9ebba2dadea7f9d5cc579963ea79c6e2936eea969bb7e5a61ce317e5a6b53e8c52b0f988b67bd35aa5a4fc28b0738dfbca3752352b7cd4d3f7a8b073801f2966a5e2a3c9a9514d160e70453576dbad40055981391c526839cddd3d8301bab76d915b0d5cf598db8adbb5976e2847262536ae8bfe4861589e23d27ed96322a27ce391f857430b87c52cb0ee5aa6ae7053aee9cae78059936d772c2c7e5627e5af67f076a46fb41b5767f9d07947fe035e57e33b03a3f8ae4083e47c38fa1aeb3c077e552e2d13eea6251f8d74e2173535230e54ebca2baea8f4c865ab1fc55836d7ec846fad886e51906196b8518d6a328b2d83b453dbee8db5477b33f5ab5121c7cd568e6946da8d65db4da7baee3d698cbb69d8111c8db45655c3063b89abd746b3dd0b2d0ceda114b52209baad5b03e6002abff00bb576cc7cd49237ab2b235214da9595a98602b5d10b2565ea6bdab46b43870efdf390d115bedda9851b7f795a26d5aabe831ab6abaafb32d6e5a5bf9b27cdf77bd472dcf5ead6e59364167a7747607157896521214f9ab4d5112308b4c8e14505b157eccf3678973776456d6c62059df7353dd37532497934d1788a7934f95195a4ddcaf7162b223abaac8ac082acbc3035f3e7c40f0737867553e547fe857196b76feefaa1f715f47c77504bd0d62f8abc316be20d366b49c7cae3e475ea87b30ad68c9d395d11561ed63c92dfa1f2e3afbfcd8a8d94367756deb7a24fa2ea53595d26d9623cfa30f5fc6b2c29e5abd54d3574785520e0f96444aa17fbdb69c50aafcbf352ecda69061777ddecb4cc876dda815a9abf37ccc3eeff0d1cd2ef5527706a44b26c0da3737cad4ed8aa17f878e7753314bbc728a3ef7fb54125952ab95f96a4dbd368ddb715561c4f1756eeb562165f46feefcd408b1e68560df779e684519dcc19a8e15471f74ff00778a1c86fba7fef95a40291f200e375148cab20059fe53c8a29580e3d41a43b7773522fde29b36fbd31502e7e5ae918d65ead42a7bd3dc73d1a8552dfecb5021140cfca2ba2f077862efc5daf5968f6417cdb86e4f6451d643f4158b0c7b9ebe82f80ba5e9da068b75af5f32add6a2c6dadbd56153cfe668482e7a568ba7693e18d36df47d353cbb5b61b46eeb29eec7dcd6dc77859374017e9596979652bee574a9c4b0ab7c922af1fc35a2a3cc652c5286e5c1ac2a9db2c55692e219c7ca2b23759bb1df32d4a896adf2a48f4fea72667fda705ba2dded8472a6f41583342637dbfc2b5ad35c0b34ff005fb57d2aa3bf9ff7aa258093d8e8a59fd183e591512d3ccf958539ec1a3f996adc07c8fbff0076ae2ac72fdddad5c7570938ee8f56866b4ab7f0e5733ed4cdf71a92eec032ee62d5a315b856df51de615335cce9e9a9d31abef7ba612e9b0c4fbb1b9bfdaa90d9c6d8f916892e6277ca9a8d279377fb359f223bb9e6f5b8afa647e955a6b7f22aff00da536f26ab4ce24caa9dcb49c1174e72bea5649556a3d520f36d5b6e777de1505cac913ee5353db4ed27df159b5d0e9578b52471babbabe9574b9f9b61abb69ff1ef12ff007507f2acff0017c1f609e58beec532ef8fdc56a5b01e5a7b28ae569a7667b5cca5052896e21d2acc6b83504756141c50724d88f9a660b7152b034945884c8f6f27751c73526cdd4d28568b0ee474be5d2b0346d2d4ac3b88a02d0abcd3950fa559820dd45899494513d8c25d856f5b42507cc6a0b0b4f2d0362a7b9b9588155156a278d88a8ea4b962367b90a0d65cd296cd3e476726a07a4d1b52a6a2319691a1a9157a71532465c85a4a06ce7612cecfcc70dfddae5fe3248b6de1bb487eef9b39fd16bbfb3b32aa37d7987c74bc5f3b49d3ff00876bca47e2a2bb30f4ed2479988afccd9e53ccf7f6eb86dbe6715eb7e0db6db6d34b8fbc702bca74b512ead06eddd4b57b6787ed7c8d2e1fef30dc6b6c5ee8eccb1f2d265cc0a876d5b68e9be5d713477a9a2ab2d35d6acbc74cc0a2c68a45291377deacf9e1dbdab6597ad569e1dc0d4d8de350e6a743cb66a8c895b3796ccbf32fddacd741934d21f3941a23f7a8f2eacb28cd30af4a7617391e293b549b47f150ca28b07390283522d3c47b734f58c37f0d3b0b9c8a8bc5ff004495bfbaa6a5f2c53a60ad6f2eefee9a2c1ce3ecf125bc6dfde50d5e35ae4223d66f908f95677c57b369a375b271f2ed15e49e2d8441e24bf4ff00a69fcc576e0749b3c2cf9f3514fcccd6b0b49e1f35e468a55518f46a759d934a9b7c9dc99e66e41fa62ac23e9eb6a16f9376e43e5b73f29a740f74aff7dd60c8622560c6bd53e44cf74f2e59557e5da4d7b3e8277e8368dff4c56bc72e547da1feeeeddf857aef836513f86ecf6ff0a6dae0c7af751f43c3f3b5492f2134e528b221fbde6b55faa96ca63b8b856f9be7ab8abc579763eab9c455a4c1e78a7ae695852b0f9c8b14dff66a7dbd5b14d688eea2c3e7217c535be5ed53326ea4607145839caed4d6a95851e57f7a9d839c8b1530ed48a3e6153c69fde5a2c1ce0a9d2adc116e34247bbb55e8213c73f354b43e72dda4678e2b4e143b4556b58996afc487ef5248caa4f4258b2bdeadc2e49e4d554c73ba9cd36d5aa471cd731c2fc61d34ac361ab460af94e6de52be8df76b1bc1b7262d5ad71f76653113ee7a576fe395fed2f09ea36dfc461f313eabcd7966897d25abc13423e68645947e1cd76534a74dc4e1aadd2a91933da23b766fef55e8ac9d715a16e609a28e55dbb6550e3f119a94b46a2b83d99acf14e5b221854a9ab68f9a815d5aa543da9a563967a8f6150cb2014f63c5529b2df35530a71bb20b893e6aacedbaa57a8d23dd5363be092422274ad2b34db8aad1c5ed5a1669f76ae3130af3d0bca9fbbac7d4b1cad6e603274ac7d4be535a389c98597be737e12ccbaeeaeac3fb95d6c3146a78ae4fc34fe4f89b5753dd10d6f4b7454fcb4e31d0ebc4272a8ec68bbc717cc4d655eeabcfc878acdd5755f2a23cd73173ae96f956ab958a952517791d2bea7b4eecd412ea41ab988ae649e4dbb9ab574eb39eee60abf76a790eabc4ddb094b638ad8852464a974ad1d6d61deff33b569a2293551a6ce0af898ded13ce7c7fe091e26b1df6fb56fe11fbb2dd251fdc26bc0ee6ce5b3925b79a368dd094746e0a91d8d7d737f0a2aee535e39f177c251c8a7c45689f32e12ed3dbb3d74d0938be56716269aab0f691dcf1f71ba9a00db4e6465f958ad22a8651fc4b5d678ec664a9ebf2e768a704dad4edb4de1b0ae19bfdafad00488dfdddad8a0c8aaabbbeee79a6a0dae76d39b08e68207c27e6f982d4f17ca9b559baeefcaaaab70557f2ab089f2f5ef4089a3259fe7f9597b5488e7685fe35eb5103b94edf42bf3354c9f2a2fd3f8691235430776f53451bcffb5451628e79ada4563b836e63b7eefdda8b66f1bd7e65fbb9afabe6d3740b953bacad7e6ff6455097e1d785af9b77f67451eefe28f8aecf62ce4fad44f971a23e6ed65f9bb2d3fcb391c7cb5f436aff00083c1acbf32cf1cfcf2af5ce4df0ebc2e998bcf9e397b3abd3f64c3eb513c86dd8c120651ff01af74860934cd1ec2c5f6b3dbdaa7dde996f98ff003ac26f84ba65cc63ecfaaed9572a048b9dd5d1dcafef42ca5599404f97d862a791a7a9ac6ac649d8823d56eedbe549996a6b6d6f5196e1618a76dce6ac69fe15bdbe9be74f220ec5bab7d05763a1f84adece412c50a371b4ccdc9af5e8d3b46f23e6f1d9953849c56ac8341b3ba640d75237cddabaa821b865d891f97ef526eb5b35fe1dc0d4526b7fdc2b4ed297c28f1e58e6f764c9a495f9a53e73fab558fb2151feaeb1bfb659b3fbca41acdda8f95d69fb0a8cc7eb50355eda66fba8b5118e68be6d9515a6b2f9fdebeeab63588593e743ff0001a8719ad1a3486262bde8bb108b99d3e5237567ea5f689fe68bfef9ada8e58ee7eefcb48f6039dbfc55cb530f4a5a4958f670b9e6268ea9dfd4e4becf2ef2ac1b72d685a59c92e377ddad46b13cf0adb6a0449623fecd70d4cbdad63a9f5184e27a553dda9eeb285fd81890bad61cb2cb19dd9adfbed40459470d5cf5d5cc5213b7eeb57054a2e2ecd1f4d86c4c6aae68bb8b1dfacaa5187cd8aaff006b3048597eed509a6f28ff00b348b72adf79ab9e503d184d16fc59a51d77407f2157ed508f3a1dddf1d57f1aa3a6b992de26e7e6515a305eac709562dd0d646992ee8979ef5cd561adceec34da8b89b1155a442d50407a55d88542885590d68830f9a8f2aae084353bec8ad4f90e6f6a91476d3b67157069e7920d491d936451c8c99578db733feca69c962cc6ba1874f18e953a58c6bdaabd99cd2c7a46143a5961d2b52db4d4806efbc6af7951c7f76a19e418aa5048e59e267534432e270959933973524df33d45b2a5ab9b52828a22e690216ab31db33f4157a0d2cb75a1536cb9d78c16a67c36e65f95456adae9e23f99aae470c302557b8bd8d73b4d6ca9a89c53af3a8ed12599d624af0ef8d570b27882cffd9b6dbf99635eaf757dd79af0df89f786e7c572ae7e5481176fe0c6b7a0af332ab0e4a6db317c3b196d5e1da3e5d95eed66be5dac498fbaa2bc57c0f1fdb3c43feec6b5edc99da2a712af23bf00d7b11df749a5541b69556a4d9bab9f94eb722bb474c686ad34543014b946aa333ca7f0e2a29946d3575a2eb55a684d2e535550c8b84e0d635cc22b72e536e57359132fcd4728fda19cc0fa531a2ab6f1ff001531936fcab4f943da95f6d394549de8da57bd1ca1ed08d9467a51b6a4dbf29db4ab4728bda0cf2be5a5317ee4fd0d4d4f551b0d3e50f6857d33fe3d93e95e51e3a8fcaf145f2ff78abfe62bd674ec7d99369dd5e61f12a23178a656c7df851abab08ad33cacde5cd40cdd36ee3b6b6daf6af72ae854aaae6a8dbac53ca1e2f2a1551b8aa31f9beb57f45fb6b6c5d3e0f36eb9509ed54e7cfda76ea11b40e9b970f1797b5b3c83eb8af4cf95197b95b96e3ef57a97c3dcb78761fab5797dfe7cfddfc3815e95f0d2512687b73f7646ae5c62bc0f5f259f2d67e86ba285be9fea2ae14f96a0e3fb4655fe1602ae2815e6729f51ed510aa53c20a9153e6a91107a51ca3f6a43e552327357163a6b252e50f6a50614d286adcb15438a3943da95d93e6a6e2ad320f4a8f651ca1ed48d12ac45150a82a645a3943da934295a76d18dd54e05e95a56df2e297207b5346de3ab5e5d410b8dbb6ada7cca685122536f5206f96ab5ccc16a59652bf782d66dccc2958d2253d46513dbc90b1dcaea50afd6bc8ecf74134b6ee7e64629f957ab5c9120af36d7edbec7e21b85f99565c4a3f1ae9c2e8da38b3157a6a47a9784f5e6b9d06d94c9f344be57e55b1f6f93eeb3b579af836f0c70dcdbeffbac1d3e86bb0b699ab9ab47966d1d9868c2a53523a0b6b93e62f2def5bd6c3e5dd5ccdb445b1b43574b6685631b8d4c536ce5c6c52d87c9f2a567cafd42d5c9d831aaa5371a6d1852d15d95f616f9aa78a13cd4891d4e9b529c605cea3b682436db4559861db51ab97a9d1f6d6ca28e49c997122f96b2f528430ad68b2d1566ea2f5a386861424d4ce2ac8f95e27bcdbfc510ad2b9b8112b337f0d66dc4cb0789da55fe2836d54d56f8b29557db4e348f41d64ddcced5af8dccc79acc584cbf2d492bee35aba2d9995b7569ecc9f6c3f49d0a7908aeef49d0becb1877a7e89a66d01986d55ad0b9ba1feaa2a15339aae29fc286cb73b0ed4a96c8492beec7cb54e14dcdb9ab7ace11e58da2a9536724eaa4ac8c9d554aad64a59fdb2d99258d2457050ab74607a835d1ea4a1b0ad546de155256a654b5b97471092b1f3178f3c2ade17d6e7b2c37d9dbf7b6e7fbd19edf515cb1cc6c15beed7d29f14bc1ff00f090684f2db0dd7b684cd17ab0fe25af089bc25a8cf8ff00476ade2f4d4e0af14a57461b4c15fa7cb8eb4e460cd5bfff000856a781b60f969ebe06d538dd1aed5aa39db39b552b29dbf79a96e232ff002afcbd18d755ff000825ee03ca3eed33fe10cba8f1b4b6dff6a8ba26e73bf77e654f97fd9a70c2aab6cdab9add4f095df0be67d7e5a8a4f0cddc7bbf85568d04ccb8bf8b695a90f41b8b2ab74ab69a548a3739f9b34ffecd998fcbb59bd6a892932b150046d4568c5a65c267de8a00efe3bc967902a4ff002e376ddd5aefe279ad2dbc951e5ba8e1abcfed2e0c685d0bfcff00ece6ba6874dfb4e99f6a967dae99dead5ea2478adea497b7ba86a373f34eb0ae36eea162d262c43a8dfab4bfecb73cd79e6b5af5e5e5f7d874f8e599b7054f29492e4d7b07c3df85c7478e0d63c41b67d67b47bb31daff008b56d085d9957aca9c6e1a3f86cf9c27f2258d71fbb6932377e15d1d8787ad6d1fcd68f73f766adbf2b638dbf36eff00c769cd0f3f2d75463189f3989c7559e97b21b6b6c164181baad5d7ca9b10fbe169202621d9b3536e8f66d976eea8949dee79d7311fcf673be2dad9e2aa4c2588fce8cd5bef6edbc3aed6a82ea1936ffabe2ba21595cc59cf3dc157e955daea4de598ed55e95ad3696dbb7e7e82b2eeada45cabc0cbe876d77425096c66e4d128d4368f9772b54b0df33b01b9ab345ac91bd266557dac777ad5fb38b0f6aceb2cf522bcefdad5a56d7f24ec554d7216ac650acbe95bf60863c2fccab5e762284627552c43bd8db5576ebb56a199a2543bcad2f9d1b27cafb78aa17cd12a3162db57fdaae2845b676fb41b7096322089a45f9ba0ae7358f0eb32196d0fe1587ae6a856f36dbc8de56436eddcd5fd1fc492a7c9feb38e77575d5cbb9e1a9db81cdaae1677a6f43165b7756dadbb72ff000b540ca572cdb7ad7737fa7db6b96a25876c53e38db5c46ab14ba7c8d14a8d1baff17f7abe7b118195367e97956794b171b5ed232b5ed7934ab41fdf6ab1e18b913e9b04b9ddb85709e32d45a49e2873f2f7aea7c09379ba3aaff718e2b82b504a373e830f8abcb94ee602385ad286b16cdc56cda374ae4f66754aa268d1b7467c55dfb0bd456af5ad6ff32d5281e657aae2ee8ce8accafcacf576dedc2354cf106fba29bb4ad1c9639a555cd1615690a5244a6a63f28aae5399bb329c8d54266dc6aece771a852d99cfca2a5c5b3ae9b5157652588b55886c19fb56a41608801714f92e628178356a8f72678a6f4890dbd88897e6a74b751c436ae2a8ddea67eea9ac5bcd4d573b8d5d92d8cd41c9de4695d5ff00bd655dde05cf359573ab7cc76fcd58d7dab9e771a5cacea8d92346ff0056dac173f76bc73c61786ef5ebd9bff1efc14576d737827cab1af36b8632dfceccff0079bf8bddaba30f0b3bb3971d3b4124755f0c137eb534b8dcb915ecd0b7cbf2d78d7c32cc53cedf2ffac3f4af5286f0e76d4568de46f849da9a369232ddaa5f2bf86a8437c76eeab515c86cd63c874fb427d86985030a721a561cedddda97207b42a302b552e7383b6b4d815aa7708d9dd47215ed4c2bbcd66c895b97310e5b159b70052e41fb5331d0d458ab8ff7aabbd3e417b52b1fbd4dceecd4c5775260668e40f6a4742d498a6b26d6a3905ed455c54a8d512d3d68e40f6a56d3182c3b54fcaac71f9d79dfc548b6f88217fe17b71fa1af42d2df7232b0dbb5db15c27c578b6eab62ff00de80ff003ade846d338b1f3e6a2d183e1d8750b9bb86df4c745bc672b1b374e9dea5f10e91aee8f711cde228676fb433796f24a18391ce540e82a1f0e432dcde430daddbd94ef32ac770bd50d335bd2e5d1af2769eeedef65f3ca3ed9732ee3ce596bd03e71952fdbe78ff00da515e83f0c1cff675ca7a495e7978a19227f6fbb5de7c2b3fbbbde57e56158d75781dd974f96aa3ad7565d43fd9d957913777aa772a7ed917d0d5fb70ccbd6bcee43e87da9224553a43445155f861dcb47207b52a888d46f1755ad3308aaf2c54720fdb19cf17cb55de2dad5a52255778a8e40f6a5275dbdaa365e6a793b542df31a3903da88339ab11a7f7aa1407357a34a5c81ed89a14e6b42dd0ad53870bf7ab46da41ba8e40f6c5eb784d5e8ed9b1505b3fb55b591bd297207b6656b9d3a495095ae7ef2da742772b5755e7345cb7ddacebd9a295cb37dea5c86b0c43b9cb36e56f9835715e3c8ffd2ad6ed06dfe026bd2ee1a3c3715c878dac05d690ec83e6886e1f855d25cb24c788973d368c2f08cdff0013485587cb3214fc7a8af49b0d34c85768af21d0ae4db490dc2ffcb2915bef7e35f4ae976d6ed6705d441592545707d88cd56268f34b98e4c163d53a4e0f72b69ba50806f356e621178a9a49c2fcab551c86358f2a485cf29cb9a44646ea6e0e46da9bef52ec14281a73588b696a704353ac752a5b7f11ad15322555220f2daa6860918f46ab9059926afc36e56b4548e4a9894910c28553e61595a8797cd6bdd4e21535cddedc331abe430a7277b9c46b4df64d77737f776d62dfce642598f7ad7f167cd730cb86e856b9a90b4b2574d3a7745cabd9d8b16709b99d5106edc6bd4bc31e1f8a2843bc75cff823c3625945d4a3e55e95e86db6ce2dab54e99854c4f4443767e5d89f2ad67958d7e5cee6a596e249dcec1562cf4f79186eaa548e49620934fb749251b83356ccb88d3fbb496f0c76c9b17d396aa37da86d2556ad5239658920bc936e5ab3a0b93e715cad3679249f2d4cb648da52bfc543a3a0e189d4d195a297e5dfbab93bed263b3bc922d89b1be646aea96d648fe654aa1aa426eedd95c6d75e8d583a66f2abceb5393b9d3471b76d557b6181ba45f94d68b154b6d8d27cdfddac999a28fe6f33e6acec45c73244aecad22edaaceb03679dd493e366e5756ddd45525feeeef9b3482e599a18370550b556efecab0ecd9b9a9c5fdbeef76aaeea1437340cc4925b38a7646f97f514c79ad77875d9506b70f97217fbcadfc2b5952cac9f736d6d15a199b4f7f132fef139cd1586aad8de646cb7fb3453b01ec71ad8d9c63ca8628d73fc2b51de5cda4aa57cb4f9b191b786ac696ee6fe22bb73cd422e8c916d7fbcc768db5ed289e19dc785f468370be4b781769db16d415d8205443b917a561787650d6be520f92df1106fef1c735b41ea9a3c7c4d44e6d320958eef94553b99de3ff655bb55b69373951f33541e436fdec2b68596e783886daf74a535cb6c1b777fbb500b9667e4d5a922932d54de12aff31fbb5d70513c1af29a77b9612e254937798db6ae477fe6fcbe776e958e539ddfc2b4d7077640e2874632328e26713a68db9cbeda591229c7cdb5b6d739e74ec3765b6d3d2f268d7efb7cb593c33dd33758f5b345ab9d362de5a2358b770c6d93ef5bd6b79bced7755e3eeb541aa5a45227ee87ccb96ad695471972c8d1565357462c32f95f77774e2b41352913e5576ace2922a04546f7dd4e8d8e42d75ce0a5b82a8d6ccd8fb64b260ac9f5a8355596f2ca4f2b779a8bc5568b1101bbe65cd6bdb29d9f36df9eb9271507747550a8dbd4f36ba568f3bb77cc783fdea86da7da4ae6babf15694d6d1f9d147f2135c1198c570771f97bd76c1a9aba3b933bcd1b58306172bb73cd6ceb1a6da788f4e38dbe68e8fdd6b83d3ef9768aebf4a98f1b1beb5cf89c3a92b9d986c4ce94938b3c3fe2269177a35fc49751edeb865e928f515a9f0deef7da5c267ee482bd5bc67e17b3f18e90f65749e5cabf3dbdc6dc9864ec7e9ea2bc8bc1d6375a2eafabe997a3cbb8b77547f4c8ee3d8d7cfe370a941b47e8d9266fede4a32f88f4581f69ad7b39871b8d6240a1936d68db385c735e1381f55ed8e92da43b856c5a49b9457356b2eec56d59cdf30a8e431a925246f451eea5fb303525aa8641cd4fb76d5f21e6caa34cae906da6c9096ab454b526ddb4f9112a6ee525b41fc552bcb1c00547777f15bffb4d58d71a8f99428a469772dcb579aa8e554d645c5e6e53b8d43757418fcc6b1afafbe5f94fcb472b368d9166e7525fbb59573a8471a16cee6aa177791aa06cb33561de5e176aa54ee5fb44917afb561caad61cf76d2b9a63cbe631a66deb5b2a6919bae44f26c52d9ae143b36edff75df76e6f4eb5d9ea398ada56feea1ae35f72db17c6e424a86f701456918d8e3c4d5e6b23b0f003fd9ad95dbf89998d7a05b5facbf366bcf3c2b118b4b83fbd8ddf9d7596538551c567385ddce9a356d148e896ecb7f155db5b93bab1124dcdf2d5a8663c567c86bed4e8e1b82d5737ff0015605b5cb568dbcdfdea5c81ed8bd513c5e6629c1cd3fef51c81ed8cabfb768b2ad58b72bb5aba4b98c6de958f3c63278a3907ed8c7917f885577fbd5a334416a84c0d1c81ed4871f3530fde34f6069bb5a8e417b5115689319a72ad238dc28e40f6a47f7aa44e9d29b834e4fba68e40f6a53b5f3165b856f9bf78715c4fc591fbed325fe2dae95db43ff1f771fed30ae47e2c26db7d39bf877bd5d38da46189a97a6d1c3592f9a92233ed56232ead82b497b6d0e9f3168af92e65dc329b4e79f534db3dac92f9a7e4da29b3a411315b79f773c2f515d27922dcfcd0c4dfc5ce56bb6f85047997ff00c5c2571973f35b2eefbd5d57c2e72ba85d45fde8c3544d5e3636c34b96a267a05f385bc83fbcd9abb6edd2b3f5060935bb63b951576cfe601ab9790f5bda9ab6a9bab4a18772d54b3b7e056b409d68e40f6a0b074dc2a0b9b60abbab480f97f86993c5b851c81ed8c39a2eb555d38ad4962f94ad547887dda3907ed4cc78866a09176d5d9a3354df34720fdaa2266dafd6ac42c7f86abb0e29f13eca3903da9ab0a6e3d6b4ad2de3e375635bdc8ad282e452e40758dfb62ab8ab836ed358d6f706b56360d8a3905ed86cd32d65dc3c721e95af2dbb3e768aa4b661dfa6da9702e358a09685f2aa9f2d43aa7878cfa64edb3eea16fcaba6b5d3655fe0add8f4f4784c6e9f7d7069721a7d6ac7c9b046d6b7b342df711b6d7bcfc34d59f50f0a4113b967b476b7fc0722bc7bc5da7be91e24b989fb48cbf8a9aedbe106a47fb56f34dceefb442258d7dd6baa70e689c31a8a1367a83066fba28f24d68c363271c55a5d299977560a81bbc62463a427f8a9761ad3360cbf75299f6665ed5a2a2632c6b29e1bd2a64cd585b6f9be6abb0d8ff11aa548c258ab8cb507f8855b93e54a47922b64aa53ea0194d5aa662eaa6ca57efb94d61cce17b5695cdc798dbaa84a15f3ba9fb3295638ef1980b6d03a8fbcc56b0b41b06bcbe54c77ad9f1b318eda21f7be7a5f045bdc2ffa54b6b2aa678665c6eaeda341ca3a1c58ac7d3a4ef3763d1b49b71a6d98dc3e66144aed76e6a179ae2ebe548fcbe3ef37347d81b6fefa6dbc75dd5aac3773c4af9f528fc3a96e18eded9434b226e5ab3fdb16483e52f27fbab59a82ce2258fcf527db22cf11a85ad161d763c8ad9fd47f0244b73e2191d76dbdabff00bcd59f3ddddcabfea155aacfdbe2f98222fd6a26d5a28bef956ff76b68524b689e6d5cdb113777332a7174b8e1fe63c5377ce9ff002d7bd6b25f477887680db4d327b6b7c0dbb56ba138ad2513cea98ec45eea6c7c13dd4a01f35d940a94f9ef9dea8d4c823da4217f94f4ab4a36935cf52306f636a399e2a3b4d9ce6abe1a7b998cd6ee91eeeb1b5733a9784bc473af956f05936d3bb7acb82dedcd7a5676af1514b2941d3bd63f57a72e877c33dc547791e397fa3f88b4c50d77a6dd2a0eaeabb917ebb6b2a4fb463cdf33e5af7b8e73c363b73591ac785743d7959e6b448e76f94cd07eedeb196157447ad85e216f4aabee3c3def6e236c45232f155a4d4eed7e677af4ad67e175c5aa79ba63adeaff00cf37e24c7f235e737b12ac122f90f0cbbb6949171b08ec41ac254547747bf87c6d3aeaf06665c5ef9aa59e4fbbdfe955d2ea3913761be6feed2cd13331dc5551ba5442358dc3ff0015438a475277069c02046580c514c9186d197da68accd0ed2e7558dbe5cf7aad0dd4b757d676908dd2cd32c48abfc5935cf3de090eedfdabd5be12f849a283fe125be1f35c0db668dfc31f77fc7b57b48f9bc455f670b9e896d64b636eb6ebfc1d4ff78d4a240b955fc69924c17e5f9999ba53597642ccddead2ee7cf4e6dbbb063b794a89e63b3ad36698226d7ddf3f4aa3be6795867bf35b42173cfab22eab891cb93f37a5576b65642ec77354b080883fdaa5ddfc3b7bd526d3d0f3ead352dca0c85a3ff66abc8b256a49208976aa6daa520f373f277ade136793561caec45016ddbb2aab56516391375654d98c9dbba9e933c7f74d6d2a6dea8c14d266aaa0948abc8db57e62bb7b562dbcbb9b763756a4332b28ddbab96ac1a3aa84d36635e3ed99d59eaa33c8a36aee6c56e5d69a2e49661b7deab2e9617bfcab5d10ad1b1d05781f90182eeecb57a1bc0d385276b28eb4d945bdb425d8aabafcb59d69b7ce1b64a5655136691a8e2f437b57b6fb7698fb3e674e48fef0af1bd621114edcd7b024affc5fc436d79c78c2ccadecb80bb5be615583babc59e9c2a2b9cf69d78c8df33eeaebf49d4cc98547656cd700988a6656adbd2eec2caaabf3577b89bf43d5e19b7c0118ee5c7deaf2fd7ad8d9f8f3536caedb88e3942d763a26a1b546f6dded5cff008e902f896c2ed47cb35a345bbdd5b3ff00b3578b8da2d45a3dfc8b11cb8989259ca5b15a712eec366b0ed6e5784ad68660abb6be69d33f47f6e6cdb4854edad4b69f6b75ac18a5f9455b8e7f7a87481d63a9b4d4993f8ab52df55ddf2b571b15e5584bedbf74d2f666529a6768da8458eb59d7dac0d9b52b9c7d45bd6ab497fbb347b2239922edcdeee2598fccd542e2f4aad5492e7aeeacdb9d43682ac3e6a6a995ed5166e6efab33d54b192d350d4edecae9de38a66d9b95b9c9e9587737e777dfaa1f6c68e512a9daca430ff648aa54c8956d0f4897c1ba4c67e64b89b6ff0079cd30785f458db77d855bfd99189ae4eefc7faccff75ede36f554fbd5dad85e0d42cadaed7fe5ac6ac7ebdeaf92c704eacfab228b44d0af2dcb258dab44d95caaf71c1fc456268da5ae81e227d3ee02cf6f7b196b7924507715e71f5a6cbaa1f0c789ee525ddf60bd61314fee96eac2ba69e182ed617f964556596375f5ec451ca67ed256b5ce6fe275b5aaf82751768d15942797b579dc5b02bc0ae7e5b7dbe66d67271b7dce057b7fc65ba16de108a26ff978bb8d7fdeda19abc86cacbed3ac69d64c3e679e153f89cd161c64cf68f0369569637b73a4cd6f148ad1a5c44245cf41835b1e30d2edd3473710dba46d6ec0e635c70783556edc695a8e91aae3e4598db4bfeeb57517c915e5b4d6ac3e5954a52683da493b943c1f696973a05bcb2dbc52365be665e5b06a2f1a69f05a5bda5edbc090ed6f2a4d8b8dc1ba558f077ee3c3d6d130f9919d4fd4362afebd6c750d1ee6dd7ef6cdc9fef2f22a6c546ab52b9c75bcabb7e5357a198af7ae76198f0ca6b4ad2efe6f9a9f21d9ed4de826dd56f358f15c8ab70cfd39a3903da96e550c2b3ae61ab7e7065a82460dde8e40f6accab886b3a603756bdc66b32e07b51c83f6a66c8299bbe6ab1326dcd5363fc38a3903da93f1411ff8f522631d69d9dcbb68e40f6a467e6a172b4bb7e5f9a9d10eb47207b633e2409a84eb9dcd80c4572df1586ed22c3fd9b83fcababdaaba94bb47de419ae63e29a7fc482d9b1ff2f23fe03c51ca4cea5d58f37b6daab22b05fbb51cbe5b67cadddb1b7a53a03d76ff007692e5e176ff00478d95b1fc3c0aab1cc3df77d986f5dcd9e6ba5f866e575e9518ff00ad80fe86b983b9603bcee6cd747f0ea52be255ff006a16a4d0e2ecee7a7ea802981b67dd9055cb1edc552d55e55855907f1afe59ad0b1ecdb6a790e9f6c6dd9e78ad186a8da7dd157a34dd4f903da96d7b714a7f780eea6a7cab4ffbd47207b52acd08aa057e635b0e9b946eaa1347f3ee5a39015532e74f9be6acf9a2ada9a10dfe354658f731a390af6c65ecf9b6ad211fdd3565e1351b4471b568e40f6c44a4aad5882fbcb71c556784b52449e537268e417b53a4b3baf9ab5edaf06e0b5c85add9571bcd6ddb5e474720bdb1d858b2cac12b49744594eeae674ed4871b4d753a66a6b3aed94ed6a974c5ed8bd6f671c4bb5453dcc6bf7be5a8ee2da67f9a27aa32453ab7cfba97b31fb53c5fe37e90b06b0b7cbf72e007fc4706b99f046b4ba2f89b4bbe66da914e124fa37ca6bd63e2a692353f0bcf2a26e9edbf7a3d71debc1f4fcf4cff00b41bfbb5aa8e844aa6a7d477fe21fb2b1487f86a9c5e2f957fd69a934d8ecbc43a4d8de9fddb4d6c8e76fae39aa1abf86dad86f4fbb4d40c5d53a0b3f13a4a06e0b5b31c905d2fcbb6bcbadfcd82708c5abb5d1a6da81aab9118cab33a016d1c7f3628760a9d691a5e2aa5ccdf2d0a243ac43732c7cee7acc9d95b2c9534c865ef5424051ab454c9f6e412bff0d539ddb3562e1aa8c92055aaf662f6e60789de3dd60ce57e5bb8ff009d7739b781373c75e77e30b81f6681d42ee49d1be6f635d45f5d333a444fcadcd7a785a2e5048f96cf6afef148bd77aabc89b6dced5cd54f39a571ba46f96ab39db190829d6f16d1e6caff00ed6daed54e315a1f3529b93d4b889249fc7f2d4998e24dcb55964dc49a8679ccb955a5c8db21cd2424d75e6e555be5aaf1dbbcae158d4896dd377ddcfddabd0a090ec40ab5ab9282d0c1b727a93411fd9a1da9f8b551bdbf1e6aa44edf5ab9a84c2d6cf6e7e6ac8b385ae66dec7f1a8a514d39c8c6b4da7ca8e8b4a67751bbb75ad22e16aadac5e441556e1e44cf3f3570c973cb43a29b718d99a2f32aa66a9cf7a149f635525b98fcbdec59bd56a9bdfc5b82b356b4e817ce684974725fe6ff0080ff000d44d772aaed41bb7566477be549f37dd6ab46692551e50f99856ce8f2ee5299ab6d7ebc237deaa1e2bf08d978a2d599d3c9bd51fbbb85fe4dea2916368b6a856918d6cdbef6037d71d7a513bb0b8b9d395d3d4f9d35bd32eb4cbf7b2b98b64d6e4823a8ac729b14ab0dab5ed3f16bc3df6cd2a2d6e22ab2d97cb29dbf7a235e3572a15cb39edf76bccab0e567dee5f8b588a4a5d7a9541f339ce28a8986ecb38720938c515858f4ae751e02f079f1578896ca51fe8b6ffbdbb7ff00a660f4fab57d07279702ac30a2c688a1405fe1038005733f0fbc3ebe15f0ba4b3a6dbdbeff0049b9ff00673f757f015b90133a6f6f9549af622afaf43e271d5f9e562d40037cbfc5493b8546dc7e5a73b08be6cfcb8accbcbcdb9fd0569083933caab3b21d261be66fbd915189a35f941fbc79aa08f26e2ce3a8a8259e4550c86bb5517b1e7ca66d8b90ca3705e2a34b9f364daa6b0a6bc0c81b3f2a9a483533e6670cdfdc1b6abeacec632773a09848db5bf871559b320e94b6af2cf1ef62cabffa155b046c1b86e55ac758bb1c15e9a6ee64cb6ecb9aa52c3220dd5b92aac8bb885db59f73e8b5d34aa3679f520914e1b965c063deb4edafd772aa8acc913af151239808ad654d4d19c66e2f43ab399e207f8beefdea4de1b08b1fca3ad50d2e5327cdbf735693cd0c40bb9af3671717ca7a34ea732b987aa969e4d98e9552085a26dca2b4ae6485a42df7554d315adff86bb6136a36b0fadc9d24f32157c37ca2b98f142a5cdbc52a8ed5d345f21f98fd2b175248a7b59d3f8a2739ff00668a1a4cf469cb995cf2fd4622920dbf32d3ace731b06dd567500bbffbab546dedbe71b4fcb5e9d8ed4cecb47bb66dacdf2ad2f8e27138d22651f765913f35535976174777954789e62b6164dfddba1f5e430ae2c653e6a6cefcb6a386260fcc8ed1cb3fcb5bb68df357310dcedadcd36e7f898d7cab81fa32aa8e822ed52afcad55a0cc98c559acdc07ed4991e97cdff6aa1c1a3cb9153e634b905ed491e63baa279768a66f1fc46abcdba442e91bb2af5daa4eda3905ed08eeef0c7f3561df5e6e62d9a2fafb92b58d713eecd35021d6249ae79dd50f9bf36ea84b6e60b4ab9db5a2a48c9d66773e0cd0f49d5f4df3ae2dfccb88a428ff0039fa8aec21b58ace158618fc9893a2ad7925a6a375a7a32dbdd4b02bfdff002db02ba3f06eb13ff6c086e2e25956e54a0f31f3b58722a654ecae439dcd1f1f596fb5b4be51f344c623f46e454fe0379a5d2a7595f724536d8ffd9e324569eb96e6fb47bbb75fbcd1961f51cd677c3e53fd83e6ff00cf599dbf2e2b2e817394f8e1386b3d22d31f7a6794fd3e55ae17c0eab3f8cf4bde3e5591d9377b06c5749f196f3cdf13db5aff000dbdb27e6db9cd733e12b69a5bcb9d4a22adfd971a4df2fbb54d8a3dc75bb3379e1d9a15fbfb37a7fb2cbc8ab9a45f9d4b4bb4bacffad8c67ea38352c4f1cb6b0cabf75d030fa1ac9f0844d6d26a9a531ff8f6b8f3631ff4cdf914ac06fdbe2042b10daacc5bf135656e4ad304355748ba3a95bdc6eff5b6f732427b700f14ac2b9e7fa9ab69ba95cda2afca8e767d0f22990de48adf2b56df8e2ca38afecef651b6294795232f5f96b3ee74d974abd6b597e6e03c6fda58cf4615bc52687cecb56d705b0ce2afc7373d6b3ed919874dd57151bf8853e417b52df9ff00dda4fb40c554762b4dc9a3903da96a59830eb59d37cac6a76718f9aab4cb4b903da94e66154dc568bad51997fbb4720fda8d854d4db4ad428e15b6b54e84e0d1c81ed46ed2d42e55b6d2b53f6f7a3907ed8ce662ba89dc3f82b9cf8a037f86d1b1f76e52ba397cc5d4cff77cbe9f43583f12515bc28edfdd9a36fd68e4055aeec794c43e6ff7853ae66825f956055655fbdbb1cd311f6be1454b737f1ca8a9f6755dabb7e7a8b1771bb0ac2558eead9f024a17c4f6cabf75832d61e36275dd5afe0ecffc24767fefd160b9eb7aaaeeb3ff0081237e46b46c4eff009ab3b55064d365da76f1f7aae6947a2a9aa54d99baa8e92d7a6e6abd1bedf9b35996f2ed153f9e31bb2acd4f909f6c68acbcd48250d59f13966157e284d1c81ed8962cb545710064df9a9f01691d77251ecc3db992e954a68bfbc6b5651d7eb54a58b6e7753e463f6c67ecdc7a51e5065ab0e370a80ee5a3d9b0f6e886540ae7fd9aa53fdead0584c9966fbb55ae212b54a983ae67b3f947e67dd5720bce06d3599709f31a816e4c476d57b327db1d7db5e6ec2ad6ed86a473b735e7d6da8f96d5ab06b4376d7a3d90bdb1e9b63e209224fbfbab4e1f11c7203bd16bcded2fc6d0dbfe5ad44bc8fd7eb4bd90bdb1db35c6997c0a3a2ed71b48fad7ca13da1d335dbfd3d5f72da5ccb0ff00bdb646c57bff00dbc2e56bc3fc64c2dbc6b7ff00c5e732cdedf32d1ecec5c2af33b1eddf0a7c4704fe06b2597e67b767b73f81c8ae96e7555bb4d847cbd8578ffc2bb93fd9ba9dae76b2489285f62181aee92e0f0b9a6a08c2a5669d8d26b68e47dd8ad2d3d4ae2b3acd5a575dc7eb5bd6f0ed5a6e08c5d52f799b56a8dc4df316ab2ede5c649ac7b99373d3842e672ab62696e462b3a798ae377ad31e6e4d56925127cb9add523275c5925182d54a471b7e614f9585569a618356a98bdb1c878da50b6476eefbc2ba7b3cddc70dc31ddf22b7e95c778b64dd6a777dedc315d268fa9f97a4daed3f32c401af5b0f4daa6b94f9cce2a7334d9b6ceb0287ceef4154bce32c9f31efc5517bd91dc73f2d321963ddd5bad74468b4aecf025535d0df50571bf6d32448e0566debba8832d1ef6f9aaa4cfe692d8dcabd2b08c5b6272d092190b4bbab66c0aafccbf7bbd6669d6a1f0acfb5987ddad0bc9174cb5dabf7df8cd6359a6f95093b2bb33b56944f75e52d5ed32c995c0c7fb555ec2c0ddc9e6bfde6f9b35be88d1a61a4a9ad57962a11318c5c9f33197372889b7f0acc925910fcc7cca75ee1a46c3f1f78564bde346c79a5468dd686ae45a139672bf2fcc2a9cb0c523166dcad8a5fb609546e0bbbd6a7f20dced68a4ddea2ba52e4dc69dca2524d87696ddd97b356c69aa5238d9c2ee6f969d6b6db9479b17ddad2b6b611fca8bb505635ab26ac38bb312d89576565daaa78357148d9f296aaeedb0654f19c50b2c79d81f73d70c9736a52ab67626ba4827b678a54dd14a0a32fa83c1af9ff00c61a037877569f4f2ff77e78377f1c47a1afa0a3718f9b6edae03e2de8326a3a626ab6b1fef74ff964f785bad615217563e8723c7fb1aea0f696878bb072e76aee1ea1a8a781309180db4579e7e8563e92bc95ef2e45ba9f97bb55a5d91204aa7a542db5a57f99b39a7cef1c4e771af6edf651f9b559bdc5b8986c619ac9fde2b6e64efb7f0a92eaf02e70bbb7567c97923a0dbbb6d75d2a4d2382ad4bb2e3c81b77f0ede06dacfbabc8e3036958d475aaf733f911ee7ddb7ef56734375792710ee5cf46aec8524b56734a4c9e5b81382d11eff7a9fa64a659162f9b7773da9d06892380abf773cedad6834f16d0ec4d8ad8e7d69cea452b211a36f32b0c2bd598a3323066f996b334db311c855a4dd566eaf444c22492bcf9c6f2b44c2a24f565f3670f39756f6a69b6813ee8eff7ab296fa1671b9d99b35762d4a28976fccdcd44a9cd195a2fa05edac3c605645e5b153f347b76d742258653bb66eee2ab4eb1ce4ed3574aab8bb339ab5152d8e7adae9ad260d5a775335e43ba3dd50dce99b4fcb55d16e2d89117e55d4f966f9a273425283e56433304f99c7cd4c0ecbf7519aafc373037c9736ebbbb9ab51881fe6876b2e3eef7a6ea5b468e88b4f628d919e4915dc36dff006aa9dfdbc76973792ca7e594efd9ef5d1452220230cbbbfbd58faad9c3757497171ff2c9384ed9f5a8a752f3d8f470ff0009e6fab5a334aceff2d66dbdd857dadfeed741e215df33ed35cab7cb37cc1abd74b43b6323762fbebb4eea8fc4571bb450cdfc3731b7e00d4166ff0028ddeb4be275f3741b854fbbc7e86b0c446f0675e127cb5632f3205906f0ad5b1a75cfce16b9db494491a3ff007806ad7d3485715f32e99f76ab33b5b1978157d3eed63d94a360e7e5ad38deb074c7ed49d8d35a5eb50cb36da87cea5ecc3da893cfb6b35b55bab190b5adc4b04abfc48d562f65158b7332b1a15317b6358f8cee25f9752b0b2bf5fef34415ff004a58afbc1ba836cb8d39ac99beb8fcd6b969ee0480d509253b6ad51b89d73d04781bc3fa9216b1be97fde8a50d55e6f86b22ff00c7adff00fc0654ae2209a4b6c4b13b2bfaab60d749a778ef56b4f95e45b945fe1957fad0e8c96c4aac9ee69e95e09bbb5d5e26d4a38ae6cb6b2bf96f8da7b1c574f0e89a5d9b896dec628d94ee07ba9acbd3bc7fa75d616f637b47fef7de4ade85e2b98c4b6f324a9ea8d915cb55493f78d6124f61dbba541a269e34cb436eadf2f98ee3fd9dcd9a9f9aa3a95b5ea4135c5aead2da6c467c322b22e066b1354789fc45be1a8f8db5375fe16f2536ff00b3b54574ff0009b48f3742d5e67fbb7739b71f4515e66d2cd759bb95d99a625cbff789e4ff003aeefc25aaeafa1e81656f17ee60999ae23dc9f7f71e4e6a945b7a14e4923d4bc23334ba2436efbb7da335bbfe06a5788e9de30b195be58b5085ad89edb8722b8ed33c4fa858dd4f2c5e56eb970f26e4e322b5751f13ea5abc50c53416b0b43209a39114e5596afd849b3175e28f458ad8b5737e0f73ff00093ead627eedc3bca9f55354a3f1f6bb1b6e6b7d39bfe024566596b37163ac7f6ac41167ded2e3aa7cdd4538e1e567721e223d0edbc73a17db3c3d3b2a6e787128fc0f35950e8875ff00065a3c5f35ed906488ff007b6ff0fe229f2fc41d46e51a1974db368a542afb5c82b9ae83c0d6c60f0ddbeeddf3b33d6728ca0b52d54537a1e7b6173b6afefdcbf2d4be2fd34691ae33a8f2e0bdcca9fecb7f10aa50bfc9b94d75c1292ba39653717664de516f99aa27a7bca5b151cbb9bb55720bdab2177eb51bcabe9f7691d0a92ad5171cfdea3903dab125218d52981da7f5abed16e5e95565434720fdab296eebc54914c69244f75a622ed34720fdab2d8fbc1b754a8c54557570ca2a552cd47207b428dd10daa44cdff3ccf1f8d61fc44f9bc2b74b8ee98fc1ab6ae805d4a15fe2646fd39ac6f1e02de19bc653d973b7eb4a50d0a854f791e4218472ad3e6be97c98a268d17e53f3b2e775445ba6da579a6d91a6cda9d8aae4b5711e9004554f90eee2b5bc2c9ff15169edfc3e70ac94489506c2adc755ad3f0ebedd72c5953eece9fce9add12f63d8efff00e41d36f3f2aa1cd58d370b1afd2a1bc78dac26dd1ee554395fef0ab7a40dd1a3636ee515d8a079d2a88d589cf0b8ab70c5bbe6aae8817e67fe1a779c59a9f211ed0be9288ea74bcfe1c56334db58ae68fb4b6e3b7eed3e417b43a0170b27de352b4dbb2ab58b6f725f1bab421b80abb68e417b525f242b1dd546e22abe6618eb552561cd1c81ed4ce6055be614bb47a6ea9a44f33e6c522286a7c81ed4aee4a81f7b6d569f2c87756b6c0c836d54b8b1f9b6a9dbbba53510f6a7377df2aff15644d9ceeaebee6cb70d9b37735897fa6c9b7e545ab5127da18a263b4b7f76a517654865fbd8a85e32b2ee6a4da181f9f6d69c885ed19ab6bac4917de2b5a31eb67d7e6ae63f0f9beed224adbba6d5f5a3910bdab3b8875b0c36eef9abcebc77f36bd6b75f2fcf1953ff000135b315d95f95cee6ac3f1866586ddd4fccb27f3159d4a7ee9b51abef1abf0f6f0c1e233083f24d13a9fc39af4cb79b74a15abc6bc3d2345ad583afde7709f2fbd7b268f66649b6b6eddf742d6305742c5cad23abd110c8e1b1f2ad6d79bf3ed5aa96e834fb75561f330a7db3ee97e5fe2a4d5f5397da176eff00d4d737792fcc6b7efe511c7b7dab9abc7f318ed35a61a374615aa952e27aafbcc8a5bf8a9d7037b7cbf7aabfef23c266bb540e7f6a4bb832fcc7e65aa9338e557f86a5670bfecd519dcee354a987b5395f180dd6df88ab1a25caff006642adf7946dc552f144a5902e3f8a9fe1b80de5b95f9be53f796bd4c32b40f2733778dcd74323d6be97a73be598fa54b65a6c712879455c6ba29fbb40ab4aa556fdd89e039a5b96a148d3f75e66efe1ab5f608d107c8b59fa6c1234bbdbeeb56e7de71cfcbc135e6d6938bb263854e64410c714509768f685aca995f50badff00332f6ad0d62e55bf7317e256ad6936c228f7b0ed531972479dee0d73be524b0b3114273515ddfac5f2aed65ab9739643cd64c9b19ca8159535ceef23595a2ac8cebabadcbf28ef549d86cf9855eb88c7a2b550951b7b2fad7a74ad6d0c1b771bb52501947cca79abd648f9cc43e6aad069334ec36ee55ee6b7ecec8c247f135457ab18ab20893daa1651b86d6a9e5c4437b6542ff769b7120b68ab12fb539bee29da0d70c29caa3d08ab5d434ea4d3df7999c85aa4ce572ea7737fbd555e47973c52c25abbe349451e6b9b93bb2ec5332bafcef9ff007ab6ed73736ce97015e2954c4e9ec7835956168ae3e6dd9cd6dc68b126d5dd5c5896b647a9805352e73c42f7c0973a76b179623fd5c2dfb97fef46791457a9f89ac448d14a119bf868af1ea53f799faa60732e6a1172dcda988823da95877931fe27f9d7b7b54f35fde5d7fa9b46546ef2d567d2679dc3cceaad8af6a8c547591f9fe2715197c264dcdc4b3bec50d56a3f222cefdbbfbd581a6d9c41d9ee1770e8168173a4227faa666f56aec73be914ce0f6d22a3c51cb26e70cc98e36d598c49b434568f51cbaf85f96110c555e7f15cdb005755a7c9565a2891cf26f734920d51b986248d71fc555e6d2ee37eeb9d4628fd7e6ae7afbc552331dd332fa6d6aa13f890b28dcfe656d0c255df4444a3cdb9d55cea105aa086d8b37ac9ddaa83df798c36fcdfc35ca5ceafbdbe41dea23ac4bb976c8db7fbb5d50c1a897ca76c6ee1c2b30f9a88af159cb23eddd5c5a6a324aff7dab5ec2f3f7815dbe6a25864909c4e992f1b03e6dd57adefe3e13657390cdb8fcb26d5ab76f39dc6b92a504d19b474f15c47226ef6e05453a6d42cbb59aaa5ade08bef27e35387124c31b76e6b8791c5824543344e417dadbbfbb4efb1ab3ee89f6b7fb35c5cda8cf65aacf69206f36290a62b7d3c470c11fcff002ffb55d92a32b2702d5152dd1bb086db87756ae475dd7e45b8bd86dc2335b6ccfd1bad50d67c67244596d3f06ae634dd465935295d9f735c2b29ff0068f5ada8619c5f348eca549c51a776f24eccefb5770dc56b0e71f31db5d14a8654dce76ba8ac2b842931563f3577234416736d0437cb526aeed2e8f3c4c3e6dbb8eda6c588d854b790f9b6536d0db369c8aceaabc59d345da6bd4c0d366dd650b63ee8db5a305cff00c0594d73fa54db56589bf85cd6bdbb86ced3e95f3ce07d8a99d8e9177c0de7ef74adf8e6dcb5c6e8b7077ec7dbd78ae9e290edf9ab294039cd0760cbfed540f3471aff000d44f249e9542794ed3cfccd51c83f6845a8de7f74ad61cb336e3562e99998f35992ca3f8aa94097506cd30932dfc550a664f969253fc2bebcd213b7e65ae8548c5d62739a3ee83f7a9bbfccfba7e6a744c5be56fbb4f905ed4954fa6dab36b7f3d8cbe75bccf0bfac6d8aa7b4b6594ad292199573baa1c135a96aa33b6d2be214f161750856e53fe7aa70f5a7e27f1369f75e0bd66e2c6e17cdfb332794dc48a5be5e95e7292fb7cb9acdf155c7956117fb4e3e5f615c55f0b049c91d94313272516732fe6fd8f721ddf236cdbee715f4d2e91058e9da558bc28c96f6f1c5b194765af9aade133ded95bfdddcf1ab85eac01c9afa765d6f4dd7a48e7d3e756da0e636e244f622bcd926b547a2da32a6f07e997938f2636b476ef174fcaa1bcf87fab4077da4f15cafa37c8f5d1d80dd7295d5a47c0a71af28994a946478d4da75e59964bab59626ff00690d4091156fe1f7af6e585594ab0565f46a81bc3fa6cafbdec2df7ff7b60ad962fba30785eccf30f0f68777ae5cc71423f7487f7b2f6515eb76f6c96d6f1c310da88a140a5b6b686d936431ac6be8ab81529fbb5cf5aab9b36a549451cb78eb4e175a23dc28f9ed0f9a3e9d0d79e4647f157b15f5a2ddda4d0bfdd95194fe22bc653e5cee3b76e73f857660bde4d1c58df75a65d89c2aeea9c7cf5495c55b85c28eb5dbc870fb511e10df7bef35579a1db8da3e6abe07f1354537f7a8e40554ce7a8e51c559922f98b7cb55b86f9734b90a554a532ffdf55136557755a9bb8cd55c865dadf851c83f6a22bfcb53a49c74ef559616ff0080d09be363b4b6dcd3e40f6a41a911f6cb5973f7b7a6dfc3359de30c3786effef2fee4b55bd46e3fd26cd70bf34854ff00b231553c52bff14f6a083e6fdc35294342e9d5f791e347ef0db4ad24ab8e5b6e3fe59f5a8f7ff1636d3509ff00797b7ad79563de274f2767eebd39ab9a3b32ea568c8597f7e9efdea8f9cacdf27f08ab3a74bb6f6d99436e5993f56a715a8a5f09ee13b37d866651b9b61c7cbdeb4b4f942dbc7b53b5527f9ace555755dca70d52e9af235b22b7dec0e6bd5503e7a554d069caafe350bdceecd49b030f9be6a922b31c6e155c8887559587992fdd0d56634957e6c54d908bf2d2a5d16f9546da3945ed0742926edf9f9b1560cbe5f7aaff00683fdfa819cc99663b9a8e40f6868a5e71f36da1662d9dbf2d67a6586e5fe1a9830405a8e40f685c59428f9a970376f5aa4973b73baac25c6ef99bd28e50f685b47daa5945182c433546930fbd8a984de667da8e50f6844f85c71556e6d830e9bb6d5b91e9a30f96c2d3e50f6a733a8695e682ca36b5623e96cbf26caef9adb7316aaefa78e5f0b4c9f6a8e13ec2cb96f999698d69fdd4f96bb87d363fe24a6ae8abfdcdbc501ed91c60b191bee256778834b9974c9a661feab0f5e949a1c790dfc553ea5e1237da2ea50a27ccd6926cfa8562294ad6d4b856b3b9e2fa7cad1cb6b75fc7148aff0091afa6f49d3e2b6856edff00886e1f8d7cb762e65b05ddf75872df5afa1bc3daf3ea1e1dd3195da4dd6caa7ea062b9e34dbd11d18eaaa29499bd7579e7c8155fee9abda6a6d6ddf7556b22d51a591401b989ad89a68ece1299566a2ac6cb9227931ad77cccafabcfd76d73f34a326acdddc9e57359534a1b2b5db87a5caac73d4ae9b0336efbb5148fb6a1727b9fbb5179a5be6fe1ae954ccfda931619dabfc354ee0ee069fe6a326e1fc5552e1db6955fbd56a987b6393f16b98e28bfbccf5bff000e844da6dccadfc320515c9f8bee372c3cb6eded5bdf0ea4db6170b86dbe60aea707ecec7263a57a373b8dcdbc8c2ecaaf0ee9e4ce3be2a4937f92521ddf30a9ec2dfecd879777cb5cd751573c171726695b24516158fca9535ccd0c11f9b2fdcc71fed1a8530c85d8fcbd6b2eea737d7596ff0052a7e415c6a9b9cb53497ba8b3a7c02498cae5995ba57448e23877636f1595651841b9fe56cd68492155273bab2aef9a561d17caae66de6b0543458fc6b31ae7cc1bddf73d4f78915ccc31f2ee148b61e5b976f99715d50508a2252727a99fe6c9b855986d8cae370656fbc2aec366276f945684568b1205f9bfe054ea62125640911d9c7e5e386f6ff6aa7791bef2fcb515ccf1c48198d65dcea1bd02799f2d73c69ca6ee6756aa8ab12dfde48d955aca9496c331a6bdc96aaef21fbd5e8d2a5ca8f3e4dc9dd96e1c2b1fa53d2e447d976d67a991b3b7d6a54566ab705d411b565a93062b85553d6b72d199be67dbf35737a74024cb33edfe1ae8a184469b58b7ca2bccc528a7647ad816de8c74cc38f941f6345453901b7ed6f4a2b99451ee46a4d2b2672f73afdc331dafb79aa13eb3272d2cadff007d565dec8ccbfc4cd9aca95e6e7757d253c3412d8f1399b35ae35a0abd76ede959b77ac96438fbd59d71f32fde6a8194afcb5d70a714162d7f6949bb77dea8a4be9646fbecbcd576a6edddf7ab6b218f79376699934ddc76d2ad03066e7ad213f37cb4bf2527fb38a064f68db7e7c5594bedac3755104a7caa693bd203a0b5d499b1ced5515af6775bbbfe35c85a6edfd5ab62d272b843f75be5f7ac6704d19491d4433961f31f96ae5acff3edcfcb8ac389c26158b55b8a7dafb9ab86a522515bc63a68674d6e1feef952ff0046ae2af3509645dbbfb57a9c70db6a1692da5c96f2ae10a13f5eff0085791dfd9cd637535acdfeb61628696165ff002edf43d0a0d34577f9bef16a34f52fa8c2b106dd9a5e31d69fa136dd6607fbbb72d5da6ef447417131dcdc32f3b76d64dcec673bbef56e5da89dba2aeeac5beb7d8bbfe55aa4734643adf0cbf353aed2492cee1621fc0d93ed59f0cf2b3045f957bb5683bf976b2a2efdaca73b6a65b1d34dea8e22c085b99d3f8735a50cbced5ac58f31dfcbbab56dbe6f99857876bb3ebb68a66c58ced1cabcad76561721a28ff8b8ae0d3e5ceedd5d6787d7f75f396e94a50ba317366dbca17e6acabcb9ebb7ef7f76a6b9982afcadf7ab0ee66db9677f97fbd51c81ed064f76acdf29acd797765b148f2ec6dcd4c3868f767bd691a444aa0b92d4a07033b76d47b873fc54f1f365eb6e431e724fbb42b1fe23f2f6a6bb8dbf2d08dbbe66a1c46a64d1b75a4ff69a9a995c73db9a7a45f316ac9c4d54c547dd581e2a9bcd9ad6df3dbfef9dc715d0a295cb28fbd5c96ab702ef589d7eeec60a176f6515c78ad2276e0df34cb1a14064d6e18987faadd28fc3a576e9398a557591a3957f8d78ae33c2596bc9ee3eeec4099fef66baa327f12eda9c3524e17618caf6a96476fe1cf1ccf677312ea01ae62fefaffac5af5ad2b57d3f58844ba7dd24abdd3a3afd47515f3b584a1a50ccd5d15b5d496d22dc4524b04eb8d8f1360d675b2f8cb58682a598b8692d4f76402a75515e7ba3fc43b983116a710b94ff009ef17127e23a1aed74bd774dd5c6eb1bb8a56ee9d1d7ea0d7955b0d529fc48f4a8e26955f8597714549b0e2a19e58ad90bcd22468a39676c0ac0e8b905e4d1db5b4d34a55511198b7b015e24f3ee3d3ef66bb0f1a78ce2d4216d334add240d8f3e7e8187f756b8a21655ddf37b57b780c3ca31729753c2cc7151949463d091253215dc76d5db7cb2ee6aa30c2cbf37e8d56e394a01f76bbf90f33da1a2bfed1fbb4c76e9c54226f987eb4c9660ac69720f9c63f7aacc39152b4a1b2b9a6bb8e297214aa156689bd2a9b7cac770fad5d7955bef1fbbfc5552572cc38a390af68339dbf29ff80d44d2b7f17cb49e705255be5a62cabbc6e34d403da142edd96eed95a3dcad27dedded4dd799a5d1ef9621f3790ffcaa5bff009a6b465fba930cd375588369b75c333790f8fca894346553a8f991e2857f87e6a474dbf3e7fe02d4fdc190329f969766d4f37ccefb76b74af9f91f5911bbf780bf7768ab3a726dbcb76fbbfbc5fe2f7a8048d228560db546d1562d4af9e9bbfbcb4e3ba14fe167b83a16b797f78abb90f2dd296ce5782d23e776c40bed53bd86cb2d8d22c8ca3652585a43f648771f33681f3afa57bf181f233a9ab27b6bd930bbaaeaea4ceac8bf32f7dd4e4b18d546ef956a2fb1c48df216f98fdefef53e423da0399546e51f4db4b92aa376ea04cd030da17e6a865964fe2f99a8e40f684af2956dcdf2aaff000d3a25fe2f7dd506f0c4eef9a9cd26ec6dddf2d1c81ed0ba9731b659b77ca6a09ae429aacf2151fc551aa993b351c81ed09bed1fc5fc54b15f48ac57f2a89d0451ff0016e53c5431e586e63f768e41fb43492f0b1ebdeae457463f96b3ed115d455f5815a8e425d42cb3efc7dda9a288a90bf79aa28232abd2afdb2fb54b893ed18810ff0010a956daac242dc363755c86d59d46d159b69029b32fec3ff4cf755ab6d31e770b8adcb6d38eedccb57fcb8a15fe15ae79d74b445a336db428a35dd35493c96d6c8530bb7057f0345fea1f29557f948ac1b8b8dc5573bb9a2952954d64653c5283b23e7385444b22b0dbb1d970bd14035edbf0bf175e12b7dbf33a3ba1af1dbb8845abdfc3f7b65dcaa7f091abd73e054b13693a8c3fc50ce8df98aa93e4b9ea637dfa1191e8f6f1a59a6e0bf362b2352767677ad1bcbd8b0cb8fbb58f7572b2e78a7422dbe6678739a4ac674f315f99bf86a84a4b36e4ab727ccedfdd53cd5795957e6af5208e4732a3b8e768f99aa1772ca769a5924192cb50b1ddf32fddadd449e6264f953efad57b8f972d52f9bb50d52bb9f744d1568a0272670de2d9ff00d321fbbd0d761f0c6059f4d9656fe19f69ae0fc51296bf55feea5771f0ce709a4cebff004d2b4ac9fb3b236ae93a1a9dfa3c48fb62149210cfd5b6d674733b6771fa5384ff002eef9979af3fd934cf21cd24497f73b5f6293fed8a6c38593e63baa1790b7cee373375a746a1be65abe5b46c72ca5777376098a80d57219a471b5873eb59b683f7429ad34fcaa165c570ca9f33b17cd645f98c2b9f915bfdaa81ef6057cee5dbf76b3a68eea721b0df376a6269f713b8c46cb571a514bde664ea4dbf7517e5d5e28fe64fbd8fe1aa726b12b9fbfb6ac2680cadba6755a9e3d06150373ad352a31074eb48c592f26b9a89a39a7216ba88f4db38fe672b4af6764a38f95aa962a2b48a17d4a6f56ce64580fe3ddbaa44b0382513762ba34b2b79183249f329a79b48b27f8bd6a5e306b06ce756c646dadb3e5635696c1b1c8dbb8d6e0b78b66dc74a60846d1f277acde29b348e1122a584516fe63f996af72a0ab52a204c6298d97dc889f37f1d6129733b9d9422a1a146f356b6b29fc9b90f9c641145725e2cb8796e123504bc795627ad15d51a09abb3d38ec55b9b79571549e1f6dcd5d1c7a6cd799f2a3dd835657c3d2315dc9b71d6bd5fad423a367868e21b4b925cec4dd51ffc237a8b30c44d2715e8a9a6595b2076a93fb42188058a35e2a1e3dfd888dce31f88f316f0eeaa8a77584dff00015cd42fa65ec1c4b6970ade9b0d7a74baaccce594ecaacf7f3673bf7355471955ee919bc4c0f323653479678278d7fda422a370172b5ea31dec80e5f6b7fbcb9a5163a35f4c1ee2c6dd9dba9db56f1d28fc512a388848f2d442d57edb459ae8ee036a7fb55e96744d2e2cf936712ae3aaad549ecd7eea454963d4b6468e6ba1c37f620df53ae8aa83762ba29612bf2ecef55dd0aa8e3ef56eabb666e6cc03661416555dd489ba27dac3bd6adcc653e6c3565dc1f9cb33afcb5aa95c9e62ec17455f6b15ad48262c85d957ad7311cebbb76f5ad7b0d4a2c8476acea46eb403a2b39b6c81b15ccfc48d2a459ad75641c4c3c9947f75872a6b7603b86f53576eac3fb7f4a9ec5f6ed99711bf7571f76bce9bf673533a284f96478fca783563c39079faaaa676fc85aa9ddc5244e619432ba92aeadfc24706b47c2ac57502dfc5b4d7a9d0efa9f0b376e52451b7f8ab3ae602f85b8936fa2ad740d6e5896cb6ec565dee9b2480b2fdea158f3e32d4cc78046ff20a9e29d9432ff794a9aad189a07f29feeaf4dd5625b8582197fda534a476d295da3cddbfe4233afcdf2d6c5a3ee8c6efbd5852396d4e6da5b6b56e58a0d81735e2c7e23ec6a694d1a30a6e0b5d6d80f2ecd1f3b5b6d737a75b1b9955153e6760b5d1de4eb126d4f955456ad1c0e655d41f6fcb9acabcb9dd85cfcaa69f7373b8f56e9541db765b3f4a71a6db21cc7b9ddf9d2ee4d855aa318c9dd49bab754ccdd41fb4353b34de2461fdded46e11b53e4279c7e032b51c2e0e690edf5dd4a8373543894a4c72395a963955be5f9a98a81fef53703706ceee6b3714573b34adadfcd7dbf37d2bce6ea7f3efee6558fe6959fe5fa9c57a18ba5b4b59e5fbdb10b579d5bfcd0176fbedb7f5e4d7998fb2491eb65976db3abf055a6ed3659b0db9e72bfeeedadfb9b7102aae37551f0447e568516d1feb65773bab52f3b6ef976d75e1e16a68f3717553ad2228776ff93ef56ddb48dfc558f6885e7f297d3756b6c923c6e4db5b729c939ea695b4aaa46eddb6b51563948955f6edf9b3fdd22b063ded8dc9f746ddd57203220db865a1c1333f68d6c6f8d67528b089a8dded51b7fd69aa575732dd307bbb89e7db9ff5ae4d557977296cfdeaaf24c57bfcb59ac3c13ba45bc5556ace44eec190aa8fa547b963f9aabbdcb7ddfe151d6a3fb42ed1f37cb8e6b4e4239d9a1846deb95f9875a89640adb71f76a9fdb61e16a27ba0cbd7e6cd1c83e7668f9ff30da57dfe6a8e5bb2cdb56a8194ee1b5fe56a03867f95d69720f9cb5e66df9b77dd15035f7c83e6dd449711e0367ef556568b3d3751c83f683dee0bcbb7f2a634873b7fbb4be58dfbbfbc2ada4b1ed0d85ddf7714b907cecc49d27dff00ecd117caabfecff156b3b0958afcbbbb7d6a9c91c6a76a2eee69f287315af4f99f67dbb7fd62e6a7be8bfd126dc76aec6c7e554f518a4d90b45f2bf98b8fceafc8a5ad995ffbadfcaa5c7466b4ea7bc8f0b540ca2a5fb344d116693cb753c77fd294a154ebf76a516f0c919de76cfb8636f2ff0080af989af799f6d0d9154249c36176b670d56b4f40d7317f12ef19a8e34ff485ddb5932766eebf8d5bb348da64da1bef06f957eee2886e89a8fdd67b9c9e4c16655f72ae0f1bb3b6ac68ab6b1592b23ac89818aab71146b09fbd244ca7e5fa8aa9a62b25a0407e5655601bf8457d4463a1f0d39bbb376e6ec4876a95d98fe1aae24668ba6ea86152b856dcadcafcd571445101b91b755722239c6362440aadf33540ea572cc576f61ef562e62f2e3db15541ba551cb51ca1ce337f96a197e55a3ce2d9551505c5b4cca197eea9a6ed29f2efa39107b424f38ab8e7e55ab2265c97c6dfe1aac90890876ffbe6ac0886e2bf2fcb472a0f68344a67728519781f354890edca63737ad4f180a3f0da6a6443b8ed4a4e20ea3228ede4de3fbbdf72d6adb677edfbcd5108cff106abf0c4171fed5434473b2c4109625b635695b5aff77d29b6510fe1f99ab72ce1dc3e7ae2ad5794b8bb95edac8b1ad38ed4478e69ca8100da6a39e6da8573dbef5704a729b35e6495d8e79962ef58f7d7eccbb95e9973761416cd643c865cd75d0c3f5679f89c636b9623a59d9d853e3b667dbb8d24295a96b019645da37277ae89cd416872d2bca47cff00e36b6367e34d66df1f2b4c651f460ad5dafc15d405b0d66d49f9898e51581f18ecc5bf8f26643febad2197f465ff00d968f85d72d17886e6157ff5b6bbbfdec15ae78a551ab9f5d5dbfa95cf5abc9fad509a4f98ed34c94c8df33540ac1b2ac6bd1a74d247cab9dd8af2f5dcf5427942c7f29a9243f21553f76a8bf75fe2aeb845137119f6e598ad4515c32766dcd4d7f994ad44a4463e63f4ad521dcb2ee581f9aa94dfbdc2d123ff00c078a8d24dcc5735690ce17c51ff002150bf37ca82ba3f87b73fbbba8be8d8ae57c5526dd7db9ff966b5b5e00b5b9b8bc3342acb0283bdfb568ed63b6b5961b53d191cc985ff00810abb022afdeaab6900897e5fc3755ddfe5e76fcdeb5c351f447ce3771af8f3ba6d5ab36d18debfad578a12e7e5f9b35a96d6ab143be57fbbc561566922a14dc992c42467f293e5dbdeaca430468259a5f9ab26ff005f82c0ec87674ae56ffc6225cb349b5ab28616a54d5688ec54d1db5c6b7676bf2c415b9ac9b9f113eedcd26df45ae02ebc49349f74d5193589650371aeea78084772f91b3d0c788f6e774fff008f66a37d70b306f3be5af3d8af2453d7e5a9a3d424fe22cbcd6cb0b013a4cef46a4d2739a993522c43316edfc55c02eb332305591b6d4e35a99587cff768786891ecd9e8235978b288ff0037ad4a35be557ccdad8eb5e77fdb326f2cceb4efedb931b73593c14587233d1a3d7f6edf9eac26bcfb36ee566af368b5b31fde3baacc1afeff00bd512c0405cacf401adbb26edcbd7f1a92df5d1bcef5f97b9ae2a3d5e3dc76cd571f568a521519b7639ac65815b586935a9d45f699a5eb2de64876499cee47c6e14560db5fe071b7a51587d524b44cd55566f25ead9c5f2056db54ee3579e52db4edaa6f2eef998eea07ef0701ab48d08a77678d2ab27a2091e5957e6346c915719fbc29fe4960769f9aadac61503616adc92466a2d94bc96fe2dd4bf666ad1884acfbb67cb8a9da355edf3376acdd66995ec6e6324479fe2a71882f6dad5a922232ee44dad4cd8aa3fdaa3db5c974ac518649130ac5ab521bc8ae5444e0ad55690272bb76d225d0864cd4ce3cfad870938b0bad362f9dd64ac49a139e9df02ba04d422c8de372e698f1d9cb9f9fe6cf5aaa75650f88db9d339a992365dadbbaf5acfb9d361973fc2b5d33e996efbb6c9b7d0542fa1965fdd48ad8eb5dd0c4c575173a38e7d2995873b97b6ea85a168beed762fe1e9d946edbb73d5ab32fb4cf2bee8f996ba215e12764cb2ad85eec015b737fb35d26997b1ae115fef571f366d8eeabfa64cd3c8028a55a92944a4eccc6f88fa51b1d7c5da8fdd5f2f9c0fb8e18551f0ac41ae5d9777ca2bb4f185a9d47c2f36f0ccf68e278ff000e0fe86b94f092ed33ed1d87cd51859374ecfa1deea29513aeb6412a2ab1ab3fd9693ee552bb8551b79b661953e5abdf690b8f2b72d44f993d0e1464dfe88325bcbdacb5cdebcb1da5848adf2b7f7abb1bcbf2c3e635c078c6fd5a130c5fc44b39ada2e5cbef1db838f35448f3c88893523b8eef5ae92ce33b3e5ae5ac49975793ff0065af41f0be946fa412b0fdc45f339fef7b579b4a3791f658b9a8415cd8d1accd8d9fdb5fe5797e54ff00657d7f1acebfbb2ee7f85735a7acdffc85536c6bf77e5e98ae6ddcb7ccc77576281e329b6ee24afbb2d512a952ad4acc725a9149ada30b20720ddd5a97961fef522fd69e42f02aec4dc074f96970768dbfc3437d69a0f1fde5a968771dfc552a36d60ad51a618d48996cf35848b4c998ed6a9043b80a6c4a1bfdecd5eb6ff696a1c47cc656bc1ad744b97c7caebb07d58e2b8d0c561f987dd738fa0e2bbff88575b344d3ed547fadb94fbde8a18d704d9b9fb342c7e5c851f2fdddcd5e363aeea289efe5aad45ccf52d0ada3b6d22cadd436f58173bbae4f268d4e12b30ddfc58ab31a340fe57cbfbac2fe5c555d4a612dc8de1576d7ad185a291f3b29f34db134c8b75e7cd5d0e2361f31ddb7b564689febb7f97b97b356df94abf363b9aa5130ab3d4af31d92165f9529c2e7fef9cd4539664ddf2aae6aab4a546d5aae533e72f79bc9dbf36d3552ee6ddf32d3219ceec67b8a91d04a7f876d1ca35233ae6f026557ef7dd1540ddcccc3e7dab5b72dadb302aa5b72f466acbbc88a7cd95ff769a88ee46b78d4437accdd76ae2a9c8ccdf2afcd43452fde61da9f28d33552f9b8e3ef5396ef71fc6b3228e46c2fddab4b0b4629728ee5bf3f71ebf76904e37fcad551a19187c86895992214728ee5cfb60fe2a8d2fc4795f95bdeb3bf78f95fe1f5a9228d30771a5c81cc6cdb4bf30dbf373b734ff2b79dcd59f05ced60ab5b36989e20eff79ba54b88f98c9d521658536ff0c88dfad5c990359bab1dbb959777d4526bb0f9961f3bedd8c9ff00a166a5ba40d0b2aa7cac39f9ab371d19a427ef23c3768662a9ea71fed53e5317faa78d96e370c6dc07c7b1a718caaf01959734d2d16f36efb646c871d8b7b66be567f133ef61f0a21489bcedceeaa9f742b72eb5a369fbb74443b59fe5017ab5508b7798bb9f6c593b0775abf6d95649586e6dc30cdec7a7e34e0bde44d4f819ee8e4793f322f4da596a3d1e269ece27508bc55bfde3d9c8a88bb99784fa8e955b4b9e58eca2f3432bed55236fddafac84743f3c9d4d5975e18a34dcbf337ddaa535e797f2d25dde9890228ac7b9ba32fccdf332f7aa50254cbff6f28e3f8b77fe3b535b4d1b39763f78d60798594eeddb9aa78643f79bf0dd4728f9cd89ae636ddb76f4e9fdeaa3f69fe251b69636dc3795ff0080d5954859b76cdbb40f9a8e525d42979d22b74f96acfda19507c8db9aad2448b8e3ef7ca2a486d3cd6dbf374e693485ed0489d982fcbf7bf86b42c636dff30a7da5b056fe2ad48222c9f4aca6ec1ce363b76ddd1b6d685ad9f9a47f7454b671eff9b1b9ab66d6dc2a6e60b5c15abd8d22ee1656512a6ec7cd56f62c4bbaa36b88a23b4fcb542e752dd5c1cb3a8ca9568c16a5d96ec6d2b5977da80e8ad5566bcdcdb55ea94926e2d5d74b0c93bb3ceaf8d725ca873bb48dd6855653b557e6a6c69bd6b56cedcf1b82b7ad744e4a08e7a69c86595849295feee3ad6c36dd3ad4edf4a44d96c85547cb59fa8dd9941e776dfe1ae16dd595ba1e8d24a0bccf17f8c3ba4f1258dc1fbcd6e5377d24ac4f87f76d078aad7fbce8d17e95d07c5a493cdb09b0bb72ebfa29ae43c3d39b6f10e992fccbfe9014fe35d2d285447d361ef5702efe67b5ac8586fc5405c799bbe6a772c0eef956a0662bf363e5af5228f932bcd29dff00ef552794abf4f97fbddea6b8768df737f10e2abb39d85986d6add20444ee7d6ab172c7fdda24b8f2fe5aac6e02b96aa45a2d3a1dbb98eea890ed2777f174355a6ba3b7e53b573cd40d79fc59aa416654ff008445fc47e229ee657f2ed22440e7bb9f415dee9f650d85b25b5bc6a9127dd0bdab27c352a5cdb4e73fbdf32ba18630ca5bef6d1595591cb8aad39b507b225566ff00be6940691fe4152a4636f5a2e2e469d6e5dc572f36b64630a2e5b934b341636c5a57dc6b93d77c5bf3fc85b6f61543c49e2132c9b1376dae1758d6d6cd3af992b1ae8a54147de96e7a54308e6d248d9d6fc46150b4d232b7615c85f788ee2523c9458d7f56acf9ae25bc72ee5999ba54b0599e3756ce6fa1f414705082bcb5248b5abc60373fcb565758bd65dab1ad312d067728daddab42dacd9f0a8199bb05fe2a5cecb9d3a4ba10c57fa8480b616a45bcd45b3b9d56bacd27c0b797c034d2259263eeb2e5eba0b7f87ba5c481a59279dbfda6da1a93aa96e79b56b508bd0f3569b50cfcf22ee63fdda679d7bbb1f68af5e8bc25a42f0ba7237bd5b3e19d39708ba7daae3a7c949e211ccf174ff94f18fb4ea1fc33d02f3505fbb2a357b53787f4e89576d8dbfb8d94c9344d2f6edfb0daedc74d942c4aec4fd6e9ff0029e34357bd8bef46ad4eb7f115c467f7b6ad5eae742d2ba2e9b6b1b29feefdeaad2786b4a9f2afa6c4cdfece4552aa83eb743ac0e06d3c4b6929c34fb5bfdae2b522d6370f9265656feeb56e5cfc37d1af01f292ea16ff0065b35ceea5f09f59b3cbe99225daafcde5afeee4a7eda1d4b82a157e1763560f104c8a305ba515c1cd79aae99235bcf13bcaa798dd0a3a7d41a2abdd34fecf7dcf6f17906ddb4f5ba8d73b64dab531d265e5d63a6ff67c9b55766eae2e683ea7cafb29761cb7b0afcdbea65d4e2dbf2b2fcc721b755292d39d8c9de99f630b8c85a5ece12159a35175b55039db8ff6aa37d502e5b359c620ce709f2d3d621b47c947b1820e6912bea264f9b7eda6b6a3bb1fbca6fd995b03e5a5fb12b765aa4a088719318f7abeb4cfb71c16c6ea93eccbc7eef6d3fec3f2fca37555e089f67220fb596a5f3a465da1ea54b31bff00d5b52c96c725907cb473409f652224337ddf31aa58ae6589ea351e5fccb4e4911b349a4c5cacd25d58ca811c6ea91e6b39461e25f9be6cd65941ff0002ef52084aaedcb560e9456c68a7343a6d374f9ea4b2d12ca073b24edc54291323ee61572268a23b98fdd1ba9ce524ac99a53726f524be81224f2bf85c143f8f1cd79e7862d45b3ddc2ceaad0c8d10ff006b0715b5e2fd7cc1049142dfbd97e51587e1f5f31657cfdf3cd74e1694a31bc8efb3f67736db6abfcc3e5a3ce3f757f869c5032edc6e6a806e493e5daab9fe2ae8566624774de6445d7e5f56af3af18dfaaacbfc35e8ba94d14566ccdb559874af21f182cfa86ab6ba65a46d2cf2b0fddaf5663d0513972c1b3d5ca29f3575d9147c1fa6dc6a7a979510f9e5e9bba7a926bd65d63d2acfec96ff007221cb7f78f726b3fc3da041e10d3162255afa61bae645fe1ff617d8555d5351ddf74b56587a0d2e6677e3b14ebd5e58fc28a57d72657aacdbbeeb0a3796cb5272adbaba1408b82e37527dda28e78abb0856cff768553fc541c52eff00ef7ad0d05c773b4ae69bce3e534bb7ad09dfeed64cd074437355a58fe60cd50c2bb454e80b2166db5935a81245f786daddb283744bb87cad597a75b995c56edbb2a2eddbf2a8fd6a6c6556764723f155a3dfa443fc2a924beffc2b581e16b4379e29b1850fcd0cde69fa20dd577e24dcf9bafc7165bf7568abfee166cd37c02a24f16dbb61b6c493367f0c578b5973626c7d2e1df26079bc99e848a5c9dc9dff008ab0efddbed32eeae91626dc17f86b9ad47fe3e9d97d6bda68f96a52bdcd7f0e49b97637ddcf35bcff00367606f98d73da0a1453c2ab66b61af39a1233a8fde12e213f79ab3e64dac1b1fed06abd7372367ccbf7be6accb998f94acbf37357621322794ff16d5e68177b5faee5a85f3bcb36ef6db4d951959598eea7ca5265afb4f9b55e72153fbdcd0998947fb4693746d956f9bf8851ca3b90c663c1651b5a924b9dc9fc3d69cf8ddb3eead52913e72ac69f294993ade6dc2d02e644ddf797a55652569eb37bd1ca3b9692e4a8f96879b9f9be6e6a9172d17cbeb4c694edeb47285cb2d31dff0029f95bb530cc71f31f96ab07f93a526ff31bf0a3942e4a972f91b7e5adcd2efd30518b36eac08636931b477db5a76304a9bb70f954ff000d4b482e696b0fbaca456f9972adfad5c98892d9f6ff0008dd54afe31f6508e7ef32fea6ae5ca4891b7dddbb4e36fb0ace51d18e33b347896425c3320f97bed6a259d306d5e35915d830edbbf1a54824c1ddebf77ea73523dcc5b1ad258f76f61b376427e26be3ea69267e8749de0994235fdf1973b5189c46bfc35b90a2ec8d31e66ec3fa8519ef59296ffbef3586d4627112f213e95a569fbb2a8c5951d795fef034a9fc482abf719ee2be6c7bb6a7d37551d3269fec68d71f7f015feb5a31f993aaeefbd81f4aa3a658491da242f32c8a7baf4eb5f611d8fcce72f79952e6e7cc90ab22b5468ad2b8fbbff7cd5f9f4a3e7e33b957bd2793e46768ff00815511ce56fb232bfcf1eea87ecdb5fa7dee95b8115906fdabba9cd671be546edb40739909015079ec3353ac45aa736db4956fbb535bc1d3ff0041a05ce2a058c05c36ead0b78be51bfeeff76920813033f7aae41097386158cd8b9c9228b915ab6f64d95dc950e9f672339e76affb55d04317960579b88af6d11a4065b59241f707dea75e4c225352cd2f949597737065caecf9ab8a09ce576156b2846c882e26697e65fbb551dce3f1a9de55c6dcd57de19b6a8aef82b23cb949c9dd90d490db79a0b63e55353456fc9663bab4ad60e42fb513aaa2b41d38393b096ba788c8e3e5dbcd68a058c7ca3eed0a028155ae9f68eb5c0db9bd4f4a11515641777614f23e5ac0ba73967fe23576ea6f90ee6acc760c0ae77576e1e9a884e573cffe29a37f63dbdc6377957017fefa5615e776d71e55cdbdc2fcacb22b57a87c4403fe118bcda19b6b23fe4cb5e4cf88a2d99fb98f95a9e2b49c59f53923e7c34a27bd2b9921597f8585546979a4b19849a6db3ff1346adf98a6bb8d9b71b994d7ab4f6b9f31522e326995e7b96fe23f7ba1acdb8b9f2eac5c1da9b7ef73f76b32e640accdfdead05120b99cc8dbb3545ee1b34f7b9695f6ad5a478940e3e6aa3a211331e4666db96a85e72957ef0c7b5b85dd5917728c9db4ae76d2a4a5b8eb2f11cba56a2db4ee47c315af59d2245d4ad62b884fc92a87af01d565d92c0eaff789535ec1f0e2fde4f0d44ccfb995d907d056555b6b4271d828a82a891d6cc56085b69fa5717e21f1016dd02fcd57f5ed6da032227f17fe3b5c26a97bb9da56a54a1cbab3928d2bbb95b54d50448d2bfde6ae2e595af2532cbeb536a5a81bcb8f9beea9e29a91163f2d69295cfa4c2e1bd946f2dcb16f0b49fecf157a188d25a26dc5741a268536a12aeedd1c4a797a4188ab1a71e6911e89a24faacc1214f97bbb7f0e2bd1b41d12d74684ac31ee760332375a4d32c62b1844310db17f8d6a59afce55bf0a99688f9ac5632559d96c4a9116c329566cd598ed8b6776ea91102a9fe2a95268a2ea6b96537d0e651422c3b7ef1dab4c92558c6edccd4d9af432954daad5516566ceedb4a306f561643a4d419810b1fcd55ccb338f9a365506acf9e1ce551692246763b856aad1e84f2364113ab36df2dab4e1b049610caed9a6c690a7cd9a98dcc0a77799b557b2d65526dfc25c292fb44b6fa6ac5d3e66a97ecfb7b5409aada2fccd2edab36f7f6f2f49176ffbd5cd273dd9d0a11d9197a9685a6eb0ca2fed20bbd9f77cd4cb2fe231456ab888c9907b51473b2af25b339e8fc4a1981693760d4dff00091755f95abcb1352963f9b2d53a6acdfc7bbe6af49e1e0fa1cfec0f538f558248f74a12a447b19db6a3d798ff00c2427fdaabd0789beeee350f0cba322541f63bf7b3183e53ad446da66caaa6ec56269de218e5c2eff97ee8ad78f588a41b57eefad66e1389cf2a089d2d8fdd6152ac0158ab7cdc52db5c070795a9d2456ced1f33563294ae0a8c50cf95542ec1f2aff155799f6a0ab2e9160a92cad58baedc9b3b295913cc761b53eb4e9a526572989ad78ae4b69cdac4595b3cd4969e26f331f76b8668e5fbee3e6c962dfde24d3d2e1a361fddcd7a0a11b5ac69ec11e9167aa4176db5d577f6ff006aac79624dcc87eef4af39b7d5bca61c56dd9ebedc27cdf31dc6a5d2fe539a78768ead11972bf36eed5611fe62ec7eef4159169ac8970b29abab346c5987e5594a0fa997b3279ae7e6dcdf8d54bcbe8d2dd99b6aeda499b79666f97d2b8bf126aa779862fe1eb574e9266b4e9734ac63eaf7ed79785b3f2d6ce8a7659a329ff68d72e72df337f15747a7c856d1557d39aee89d9898a8d3b23a38e691c6576b2d5a836cf19fbbbeb26ce4dabb7f85ab466b916d0195f6fcb5138f63cf39af135efd9d58c8772a765eadec2aaf877413a289757bd3bb56bace777fcbb29fe11efeb576d512eae5b56b8f9b6316813dc7f1fe1daaadfdf1f99b35a72736fb23be8549462e9c377b906a5a873f2d623cc647a269da573cd46bfddcd6963b29c14558783d78db43e29ae76d377d16351ea69ecff2f4db5072df785498db8a603d7a6e6a46e9ba914155a3ef638acd80bcb7dea72e36ff00b348071b569fb36aff00b359b289623b715700dbf77e656e82a9c7f3fccd57ace32d354584e5645fb384afcca376ee95a1bfe5094c894c0a157f8734e49226986e0bd68b1c529734ae79bf8be58e7f145ecb9dca8f1c5f2f3bb6ad68fc3accbaade5c63f750dbedfc59ab9cbbbb8e6bb9aebe5dd7124d2e3eadc575fe024912c35295a35569648941f650d5e1d1b4f1373eb7149d2c05bc923b78653b19bf8715cf5eb8690b20dad5b1f6931d99fbbb79f96b9e964dce6bda68f95a26ee9436db6e7a9e4b8f2d471b7fdaaab67385b5098a49a5ddf2a9f96a94499ee48d75e67c943244df36372b5674d315cff0077351b6a355ca22ff0b95f976f6aab7373f36d53f5f96ab35f99142d5679979dc7e95490c9cce7d5b6e6a3fb4b3542ac24a7c36e5be6fee8a2c05985f795fad4f35b2c90eefbaca76d5442533b7eed5c4b82ff002aed5a2c17335daa2fc6b4eea146cb62a8329534587cc3031932b9a6b215a5ddf38a953e65a2c1720ec56a68ed8d4b1c07efe7ee9e6aedb4277965dbb681730fb3b3daa3e4666c56bdb21651b53b7ce36d411baec1b4569c78dfd3e75159b21d4453d4bcafdd2ca76af988a157ab1cd4b76fe54336e1f741cfe59aa77e88f342b2bb2b34cb82dfc441ab97ca62b399b1e6af96df2aff0011c5448233bb4789a66460cdbbdaa796e552396d658772b30f9a45c479f7c51696d1ed2ac5be61c2d596bc305acb62d6bb95df779b2ae63f5af8d9fc4cfd2e9fc08c985035cf9adf2ab31f923fb8bf4ad7b68ccb2c2bf2ed415962df6cbf6acfcd292fb17ee2e7d2b66cd3cb9a26f9955f0a7e99cd14fe244d67ee33db2d587941264f29b03f8bee9aa3a317b6b355f3165405be65e075ad40372a330fbd599610c4b66be487d9f330ddf5afae8599f97559bbb341e50e06daa3772b2fc8a94f866ddf27fe3b560c4af11ddfc555b197332a467680af56e27dc8556a14b5f98355c86dca64e36d126839989e5afdea7c0bb7098f9a9c80ae7e4ab16d136ff993af7aca52b20b93416db986e0dbab5ecec361dd8a4b5b293e467ad489020ddfddaf2ebd76f4468844844786fbded5289d553e6aa77374a9f75be65aa52df332573aa4e7ab13c4460ec5d92e8cbfbafe206ab4de5a0decff0031a89ee6ab4d31cee6f9bf86b78523927579ddd84afbbe651dea4f2f763fbc699092bf355c8623c3b56b29728a29b15222a816b4ad115610d8aad6b13efdcc6b43bed1eb5c55657d0eda14fa913b1605a2aa572adb767e756e6936b155accb8bddbfef669d28b6f437650b9322ee27d6a8bbfca6addddcfc9f2fad664cfd5abd5a51763366078ce2173a06a68fbbfe3dcecfa8e6bc737ee42cc7e6c1af66f12396d1eed54afcd032fe95e2cf32b46530df202a2b9f1cadca7d570ebf7268f63f0f5d06d06cde23f2f9617e6f6a75cdc9cd73be1bbf68bc3f6ccbfc4bcd587bfdd9af4a9db911e1e22935564bccb535c0e594ed5ac9b9bb0d956a65c5d9ddbbf85aa067565dac3ef5584288f8f14e95ce4eda8c7f756a198edf973b79a2e74c692239a62cc57354ae086cd48f2ee277166aaacc17e56341d94a3631f5f1b6de36feeb7f3af4ff008779b4f04dbccdf76592573f81c5797eb3f2db956ff7abd5ad01d33c07a145b9771b5129f462c4b562dfbc91d38b873d051f331b57bc32dc492b16db5c9eb37e5b31237ccdd6b5f52bbda8ef8daab9c0ae5ae599ada499bef39ab94ac8583c32e6b9987fd9f5ddbab52d53e51fdeacfb65f34edfeed745a26986f2f12dd6a13bb3d1af2508f3336342d064d49b7b1db103c9fef577d631476d108953e551f2551b68a3820544f9512b451b6f6aded63e37158a9d795e5b17614dc76b7dd6ab96c8ab26efe1aaf6f1ed1bdbf0ff006aa43204566aca5ae873a8965ee76e795dd55dee8337f7bfd9acf69d986d54ab3691ee5567fbadf30353ca90d26c9a2432e5f1f74d4e2d374aad52c3198d7a6edd53a9ebfecd65299d11a3dc4b7846eab1b82a74a832d263654e96ecdf7bef7a56327dcde3488a5884b55bec61bf81be5ad34b73c2b7cb563eceabfeced153ed6c52c3dcc51a51971b63dd4a7442bd956b6c5c4500dbbd77531efedd87ce6a7db48bfaac4c73a53aa2a47338c77ddeb4569b6a76ebf298d5b1451ed65d85f568f73fffd9);
INSERT INTO `tbl_empdata` (`employee_id`, `first_name`, `last_name`, `face_image`) VALUES
(46, 'Cherry', 'Lopez', 0xffd8ffe000104a46494600010100000100010000ffe201d84943435f50524f46494c45000101000001c86c636d73021000006d6e74725247422058595a2007e2000300140009000e001d616373704d53465400000000736177736374726c0000000000000000000000000000f6d6000100000000d32d68616e649d91003d4080b03d40742c819ea5228e000000000000000000000000000000000000000000000000000000000000000964657363000000f00000005f637072740000010c0000000c7774707400000118000000147258595a0000012c000000146758595a00000140000000146258595a00000154000000147254524300000168000000606754524300000168000000606254524300000168000000606465736300000000000000057552474200000000000000000000000074657874000000004343300058595a20000000000000f35400010000000116c958595a200000000000006fa0000038f20000038f58595a2000000000000062960000b789000018da58595a2000000000000024a000000f850000b6c463757276000000000000002a0000007c00f8019c0275038304c9064e08120a180c620ef411cf14f6186a1c2e204324ac296a2e7e33eb39b33fd646574d3654765c17641d6c8675567e8d882c92369caba78cb2dbbe99cac7d765e477f1f9ffffffdb004300120c0d100d0b12100e10141312151b2c1d1b18181b362729202c403944433f393e3d47506657474b614d3d3e59795a61696d72737245557d867c6f856670726effdb0043011314141b171b341d1d346e493e496e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6effc0001108066004c803012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00e1e9475a4a0500588fa53e991f4a7d0014b4945002d2d251400b45145002d1494b40094514500145145001494525001452514001a864eb529a8a4a008e8a28a0028a28a0028a28a0028a28a0028a28a0028a28a0028a28a0028a28a0029f19c30a65393ef5005d1c8a29a9d053a800a28a2800a28a2800a28a5a004a5a28a0028a28a0028a28a002928a5a002929692800a434b41a006d2d149400a6928268140051452d002521a5a69a004a434b4d3400d6a653da99400b4a2928a064917de156c7155621f355aed4088e73f2553ef5667e955875a005a5039a29475a40588ba54a7a54710e2a4a801a07cc2ac2f4a807deab03a55a01937fab3596ff0078d69cc7f766b31bad301b452d250003ad4a3a5462a41d28010d369c692800a4a5a0d00368a5a2801314b4b4aab9a0017a52375a7e314c6a0055a463480d213400035229a8a941c5004d4b4d539a5a004345149400514514000a7014d1d69f40098a4c53a8a004c518a5a280136d26da751400ddb46da751400cdb46da7d2500376d26d34fa280198a314fa28023c518a92931400cc525498a314011d2d3f028c50047453f6d1b68019453f6d26da006d14edb46da006d14bb68db4009452e2931400514628a0028a28a0028a28a0028a4a280168a4a28017345251400da05140a009a33c54b50c7528a005a28a5a0028a28a002969296800a28a2800a28a2800a28a2801292969280128a28a004350bd4a6a27eb400ca28a2800a28a2800a28a2800a28a2800a28a2800a28a2800a28a2800a28a2800a55ea2929475a00b687814fa8e3fbb4fa005a28a2800a28a5a0028a2928016928a280168a4a280168cd251400668a4a280168a4a33400b494b4940094529a4a004340a5c537bd003a8a4a2800a434b4940094d34e34d3400c6a6d2b520a00514b494b40c9a1193566abdbf5ab1408af71d2ab2d4f727b542b400b4abd6929cbd6901662e94fa645d29f52022fdfa9b38a893efd4a4719aa403263fba359add6afce7f778acf3d698051494b4000a9074a60eb4fa004a4a5a4a002929692800a5140a5a0029e9d2995228e28003513d4a6a26eb400da4a28a0028a296801c95254694fa002929692800a28a2801453a9052d001451450014514500145145001494b45002514b49400514b494005145140051451400514945002d145140094b45250014514500145145001494b450014628a280131462968a004c526da7525002629314ea4a004db4629d4940098a4c53a8a006e28a7514011514514012446a615047d6a71400b45145002d145140051451400b451494005145140051451400525149400521a5a4a004a89ea53513f5a0065145140051451400514514005145140051451400514514005145140051451400528a4a05005b8beed3c5470fdda9280168a4a28016969b4b400b49499a42680149a2933522a8c64d00328a76da63360d003a8a6efa42d400fa426984d19a007d14dcd26ea007668cd33752e6801734669b4b9a00334868a5c5002669734629280168a40683400869a69d4d3400c3494a69b400ecd1494b40cb16fd2ac66a080616a6ed408a973f7aa3534fb8fbd51ad003e9ca29b4e5e9480b118e29c69b11f969e6a405887cd521a8e21cd4c0552020b8fb959ec39abf76709546980dc514e1498a00075a7d340a750021a4a53494009452528eb400f0bc518c5397a521a00631c53d1f8a8de9a0e28027269879a6eee294500211498a71a4a006d2d068a007ad3a9abd2968016929692800a28a05003d7a5140e945001451450014514500145251400b4514500149451400514514005145140051451400514514005252d140094514500145145001452d25001451450014514500145145001451494001a4a5a280128a5a280128a5a4a0028a28a008a8a28a0072706a71d2abaf5a9d7a5003a969296800a5a4a5a0028a28a005a2928a0028a28a0028a28a0043494b494005252d21a004350bf5a94d44fd6801b451450014514500145145001451450014514500145145001451450014514500145145005980fcb52d43074a9a800a28a426800a375349a2800268cd25266801e2a50df2d57079a9541c5003b350487e6a9cd57931ba800069734ccd216a00933466a3dd49be8024dc69334cdf49be80250697350eea371a009b3466a20f4a1e8024a036299ba8cd004dbb3484d440e29c4d0007ad2e69b9a5a005a6934134d268010d20a5a050014a3ad14aa39a009e3242d3b711489c0a53d2802b4c72d4d514e93ad20a005a940e05442a51d29012c638a71a621c0a7139a901d11f9aa706a08866a6aa4056bc3c552ab7786aa0a6028a514a052e2801b4b462928010d21a534d340094aa79a4a17ad004e0e69a4d18c0a693400d6eb4da5349400a29e3a5305482800a4a75211400c3450681400f14b48296800a28a2800a5149403400ea5a414b400514514005145140094b4945002d1494500145145001452d25001451450014514500145145001451450014514500145252d002514b494005145140051451400514514005252d14009452d14009451450014514500251451401151451400a2a74e955c54f19e28024a29296800a5a28a0028a28a0028a28a0028a28a002929692800a4a28a00290d14868010d44dd6a5351375a006d145140051451400514514005145140051451400514514005145140051451400514502802780d4d55e2eb538a005a693433629b400b9a3349450021348694d36801ca706a432e05424d373401234a4d4649a09a6e6801734945140094514500145149400b45251400b45251400b9a5cd368a007034f07351538362801f4669bba8cd00389a4a6e6941a005a5a4a33400b4aa79a414b401329a563c5460d2f5a008dc73401526dcd1b71400c1d6a4a4c0a70c1a0095318a5205317814e0722a407c438a782334d886053c8cd3029de75aac2a7bae1f1500a604829690529a0043494a692801a6999a7b74a8e800a51d69281401286a69a1694d0030d2538d2628001520a6014f1d280168c668a70a0089860d2548e2982801c296814b400945068a00434ccd38d3475a00913a53e989d29d40052d251400b4514500252d14940052d252d001494b45001452514005145140051451400514514005145140051451400514514005252d25001451450014514500145145001451450014514500251451400514514009452d14010d145140054b154552c468025a5a4a5a005a4a296800a28a2800a28a2800a28a280128a5a4a004a28a2801290d2d250021a89bad48c78a88d00251451400514514005145140051451400514514005145140051451400514514005028a5a0092238352935021c54abcd0018a5a5c514000a463484e29a4d002d213499a6e680173494514009452d14009494b45002514b494005252d2500145145001451450014514500145145001451450014b9a4a280173466928a00706a5dd4ca280240f4e125454b40132c829dbc1aaf4e1401293499a68a5a0078908a707a8734b9a00bb13f18a933cf154e393153a3eea00ab75feb0d422a5b8fbf510a009052d3334a0e68014d252d250035fa5474f634ca0028a2940cd00397a52d00628a00434828634ab400b4b494a280169c29b4a28007e94ca73734da0070a5a414b4009451450031a9052b75a17ad0048053a9051400b494b4940052d252d0014514500252d251400b4525140051452d002514b494005145140051451400514514005145140094b45140052514500145145001451450014514500145145001494b450025145140051451400514514010d1451400549175a8e9f1fdea009c52d20a5a002968a280168a28a002929692800a28a2800a4a5a4a004a28a28012929692801ac2a2353374a85a80128a28a0028a28a0028a28a0028a28a0028a28a0028a28a0028a28a0028a28a002945029e8b9a00117353a8c0a455c53b34001a6134ac7151e680034d34ea4c50036968a2800c5252d2500145149400514b4628012928345001494b49400514b450025145140051451400514514005145140051451400514514005145140051451400b9a5069b45004aad4e0466a1a5068027e29a4530353c371400de94e0e41eb4b8069a45000efbbad3294d250014a0d3696801f4869053a80236a6d39a9b4005397ad369cb400fa434b41e940119a55a434a2801d4b494b400b4b4da70a000d369c7a53450028a5a4a5a004a434b484d0030d3905369e9400fa5a4a280168a28a0028a28a00292968a004a5a28a0028a28a0028a29280168a4a5a004a29692800a28a2800a28a2800a28a2800a28a2800a4a5a2800a28a280128a28a0028a28a0028a28a002929692800a28a2800a28a5a004a28a28021a294f5a4a0029ebd6994e06802c2f4a5a6a9c8a75002d1451400b45145001494b49400514514005252d25002514514009494b49400d6e9511a94f4a88f5a004a28a2800a28a2800a28a2800a28a2800a28a2800a28a2800a28a2800a502802a445a00454a954714a169d400869a5b14ac698680109cd252e29c16801a052e29d8a4a00691498a7521340098a6d2939a4a002814014ec500252134a69a680128a28a0028a28a0028a28a004a29692800a28a2800a28a2800a28a2800a28a2800a2968a004a28a2800a28a2800a28a2800a5a4a2801d4a29a29c2801c1a9c0d329450039803d2a3a7e682334011d14a451400a29dd2841c52914011b0a654b8a611400da70a4a51400f141a28cd00467ad28a46eb4a280169d4d14b400b4e14da70a000d2014e238a68a005a4a5a280129ad4e34c340095220e2a31d6a61d280168a28a0028a29680128a5a4a0028a28a0028a28a0028a28a0028a28a004a5a28a002929692800a28a2800a28a2800a28a2800a28a2800a28a2800a4a5a280128a29680128a5a4a0028a28a0028a28a004a2968a004a28a2800a28a280237fbd4da7ca306994005028a280278b9152e2a284d4b40051451400b45252d001494b45002514514005252d250025145250014869690d0034f4a88d4a7a544680128a28a0028a28a0028a28a0028a28a0028a28a0028a28a002940cd0066a68d280044a942e0538000514c433341a52314d3ef400ce680334f033522a803340c604c0a538029cc41e94c6e7a500349a434edbc52118a403290d29a4a004a00a5c51400519c0a2909cd00349a28c51400514514005252d14009451450014514500251451400514514005145140052d252d0014b8a294500371453ce3b5211400ca29d8a4a004a28a2800a28a2800a7034da5a007834a066994e53400e029694734ed98e4722801853238a8cf15692a39533c8a008d1b06a6e08aaf8c1a7ab5002375a43cd388cd348a006d28a4a51400ea0d1450031bad0295a9b400f14b4829680145385345385001494a692800a28a4a00434c34f34c3400a839a945469528a0028a28a00296929680128a28a0028a28a0028a28a0028a28a0028a28a0028a28a0028a28a00292968a00292968a004a2968a004a28a2800a28a2800a28a2800a4a5a28012969296800a4a5a4a0028a28a0028a28a004a28a2800a28a2801b375a8ea698719a86800a28a2802680e0d4d55e2fbd562801692968a0028a28a0028a28a004a28a2800a4a5a4a00290d2d250025252d21a006b74a88d4add2a23400945145001451450014514500145145001451450014e03348066a78d28008e3a940a503029d8a6213141e0529cd20f7a004e3a9a637269e691539cd002630290b1a563cd30d002e734a05228ef4ac68189bb14d2734b826908c1a40250066940cd388c0a006118a4c53b1486801a69294d250006900a5c51d28003d29314b49400945145001494b494005252d18a0028a5c525001494b494005145140052d145002d028a5009a0055eb5204a722714138a006b007a0a8ca1a9d573cd39fa74a06532314952b8c9a61522810da28a2800a28a28016945251401229c54a8d50a9a7fb8a00b1b38cad18cf069914983835390a70453115a48f150d5eda1860d5596328ded486341a43494bda80194e5a69a70a00514b40a5a008da9b4f6a6d003853a9a2968016945252e6800a29296800a4a5a43400d34da5349de80244e94fa6a8e29d40052d145001451450014514500251452d002514b45001494b49400514b494005145140051451400514514005145140094b4514005252d2500145145001451450014514500145145001452514005145140052519a42d400b9a42d4de49a0293400bba8a50945003a61c54156641f2d56340051451400f8fef5591d2aaa9c115654e45003a8a28a0028a28a0028a28a004a28a2800a4a5a4a002929692800a69a5a4a006b74a88d4add2a13d6800a28a2800a28a2800a28a2800a28a2800a5028033522ad002a2d4ea3029a8bc5480714c42538500518a00775a69a514114c040b934929da302949c0a85b934804a51c9a4c5380a005a08a514801cd003b1b45447e63523127814b8007bd00478a08a7e30293ad00331498cd3df8a8f34862114da7019a2801290d29a6d0014514b8a004a4a76293140094629714a17340098a31526dc0a61a006d2538d250025145140094b4628a0028a2945002a8cd48a314d5a9074a0076702900279a40371a9d1290c13eee314d73818a91f85e2a25cb1e68191edcd1b38a91801d29ca78c6281151d6a3c55c74f4aae50e69888e8a7118a4c50002940cd18a51400629ca48a514fd9c5000a334e56238a629c1a9000467bd3112a37ad128df4c53520340151d769a61ab92c5919155197071486329c2908a050028a7669b486800279a4a292801c29c29a296801734669a4d19a0070a5a6a9a7d002521a5a43400d340eb41a541cd0048296814b40051451400514514005145140051451400514514009452d14009452d250014514b400945145001451450014514500145145001494b494005145140051451400514b45002514e084f6a564da39e28023a291881d290126801d9a6934a013d6976d00300269c129d8a701c500336d28a5a0d00145251400f7e9550f5ab8466aa3f0c680128a28a0051d6acc6781556acc3cad004945145001452d250014514940051451400945145001494b494009494b49400d6e9509a99fa5426800a28a2800a28a2800a28a2800a00a29e8b9a005515346b9a454a9d1368c9a6203c2d37750e69a050048a68340520669680133485a94e05309c53010b53392d4b824d3c280290001c518a37629e838a0040b463b53b38a6e7073400aa02f5a00c9cd1f7a909c7028015864d232e0539781cd359b2680217eb4c35230a6e39a431070290d2b5275a004a314e0b4e238a008a969718a3693400da705a5098eb4bd680055069e5428a4030326985b2680158d329dda9a450034d253b1494009462971486800a4a28a005a7014d14f1400a29fd6a3a950714864883029dbb02a30d8a7819a0a42a82e6948c35488b81c53827cc2a6e5586a45ba95a020f153052b522a96a2e3e529ec1dea39231daaec90f7a85d08a1313899ee873d298462ae3a67b544f1fb555ccda20c52e294ae29bd29885a72b1069b9a5eb4012601e68191d6a30c45480ee1400f5e69cac41e6a35ca9a7b1cfd6988796f4a8665cf34e46c1e69cdcf22802a1a075a7baf34dc5218edb95cd466a5078c544d400da28a2801453a9a2968010d26694d36801ebd6a4a893ad4b400534d2d34d00253929952274a0078a5a28a0028a28a0028a28a0028a28a0028a28a0028a28a0028a28a002928a2800a28a2800a28a5a004a2968a004a28a2800a28a2800a28a2800a28c539632dda80194a149e82ac25bfad4ab105a00acb0b1a996003ad4c05231c0a0063058d7354646691ce7a54d33ee6f6150d00205a7018a29734005068cd21340053ba2d47ba82f400ecd216a6e690d0038b514ca2802dd5393ef9ab86aacdf7a8023a28a2800ab1074aaf53c07b5004d4514500145145001494b4940051451400945145001494b4940094869690d0031ba54552b5446800a28a2800a28a2800a28a51400a066a68c531454a8326802445a7335213818a66734c407934f4c0eb4d14eebd28014bf14ddd48c299400fce6918d038a5c5002668a0d2a0dc68015533536dc0c520e060504e053018d4d51b8d04e4d48980b400870a29a9d7268277b7b52679c5201ccd934ca75231c0c0eb40119e5a8229d41140111eb4aab4f54e69f8c5031b8c5348a731cd21181400dc669caa7ad22ae4d3d8ed14806c8d9e2982947269e138a6030f229a12a4db934e380290111e29b4e6e69a0668010d1d2948c5250034d2529a4a004a514629ca39a0000a5a5c628a060a326a514d51c5488a49a4342ac64f4a940c0a9163205010e6a6e68a222023b54eab93d29c880015328a9b9490cda31428c1a9314a139a43b08464546d1f1d2ac6da4db45c2c5268c542f155f64e7a544e9dea9325c4ce78f1daabba62b51e3c8e95565871daa933371b146969ee845475440126955f1484714da00b28e1853f1d8d54562a6ac23eea0057056951f8e694f4c76a88fca6801cc01a8cf14ece690fbd00333484e452e290d00368a5a2800a09a290d0021a28a2801f1d494c8e9f400869a69c69a68013bd48bc5463ad4a05003a8a296800a4a5a2800a2929680128a5a280128a5a280128a28a0028a28a00292968a004a5a28a0028a28a0028a28a00292968a004a29ea85aa4580f7a0084293d2a45889a9d100ed4f028023586a5080528e28a0028a297148000a8ae182a66a52702a85cc9b9f19a00613914ce946fa6b366980edd49be999a4c5003cbe6939a02d2e2800028c52d14005069692800a28a2802cd579c60e6ac5413f4a00828a28a002a583ef545524270f40166969052d001494b4940051451400945145001494b486800a4a28a004348694d250031ba5446a57e951500145145001451450014f514d029e050039466a74c2ad3117029c680109cd1494e514c42f6a507029a4e29a5b3400acd934828032683400b4e0d814da693cd003fa9a91060d2438ef520009a600bc9a4734fc802a06396f6a0008e697b629179a781934009c2af1d6a30d4f7eb518eb480914e39a31939a45058e2a529814010914019a73d0831d6801eaa02e6a366dd4e6271c535579a001533c9a732e69fdb8a38028023e14540c4b1a7bb6e3c74a451cd002c6beb521a062919b1d28011885151fdea5c1634fd981400cdb49d29c4e298690c43cd31b8a71a69e680128c52e2940cd00201522a50ab4fe940c61eb4f44ee69523c9cd4cb193d295c690c0b9e054d0c3cd3a34c55844a96cd231140005204cb74a97653e3515068342f140041a948a455e680140cd48a98a153bd498a4047b694af14a452f6a008b6d31d2a7205348a00aac9e951347b855b75a8d96aae2b19d3c18154648ca9ada65c8c5559e0c8e055266728f63301ec69ac306a69622a6a2cf1835664329cac41a4231494016124cd2b0cd40a706a556cd0020e294d2375a51cd0035bd4520c114f1e94c61b4d00262929e0e6908a006d21a7534d002514514012274a7d353a52d0021a69a71a69a00541cd4a29918a92800a5a28a0028a28a0028a28a0028a28a0028a28a0028a28a0028a28a004a2968a004a28a5a004a28a5a004a2834a8a59a801550b54c90fad48881453e801aa8052d2d14804029d482826800a514829d4c028a5a29010dc3848cd65b3166cd5bbe932768aa78a007229634f74db5240b819a497ad00438a5c52d14c028a4a5a00334668a2800a31452d002514b450058a8661f2d4c6a394654d0055a28a2800a747f78536957ef0a00b83a52d22f2052d001494b494005145140051451400869294d2500251451400948694d250031fa54552bf4a8a800a28a2800a28a502801ea2a4005220a5ef400f068a00e28a0014714e3d2940e2a276c1a600e79c52014deb522f4a4028e941e05078a61340016a45e5a9b9e6a445a622741c548c42ad3147cb4921c0a0069634d3c52292c7da86e4d00489d29c5b68f7a8836da42f9a00731cd22ae69abc9a9f031400e8c6053998014c0c05358e69802aef6cf6a1c60f14e1f2af14c24b1e6801579a785a8c1e6a6c855a00616c544ef9e29643934c55c75a40017029b9c53d8e07151e32680143734ece6902d3d57d6801506295cf14ee3a0a4619a0087ad349a7b0c530d218d3498a775a72a50035509a7edc53f381814d340c0714aa0b1a154b1e2ad430f4e293652571228f356426062a48e2c0a944750d9aa56218e3c9a9b6014e45c5382e6a46371428c539978a555cd03100cd488b9a5550053d13bd003953028229f8a31480888cd0053c8a691400c2290f4a7d2119a0645d4d35854bb69a4500572bcd3592a665a6919a6228cf0023359b34454d6e3af154ae20ce715516672899548454b24654d455a18894f53834ca514012139e68534dcd140121c5239c8a01a43d2801a29fd453053874a004229ad52629a4500474538ad26280254fbb4a6841c50c31400da69a5349de80248fa5494d51c53a800a28a280169296928016928a2800a2969280168a28a004a29692800a28a5a004a2968a004a28a2800a28a434009824802ae431ed1ef50dbae4ee3568500145145000283474149d680145068a66ee71400f14e14cce0522ee2f93d28026a648e114934eaa57d2f1b45202ac8dbdc9a68193482a4857735004ebf247503b65aa79ce17155a800a28a514c0314b8a28a004a514525002d149cd2f3400a05149450059a8e4fba6a4a637434014cf5a29587349400528a4a2802e4672a29d51c3f76a4a00292968a004a28a2800a28a4a00292969280128a28a004a69a71a69a006bf4a8aa56e951d002514514000a9516a3519353af0280168149de9ca280158e0522f2691fad28e2801eedb5302ab9e69ecd9a650002a4069829d9c2d0038f34c6a375039a0011726ac228c546a314ecf1814c43fa546e73c53c7dde6a23f7a801c0e06292933cd216a001f9a545c9a6e734f53c62802509e94adc0c500e05358e78a60253d3ad2aaf1cd23714003f0714d6e0714a3919349c77a40341c5297a4a4c66801339a0b628600535b9340099c9a7aad340a91680155734a694900530364d003d7a5048a4dc314c268011bad32973934e5418c9a430029c0629075e29c462818c3d69429634f55cd4d0c449e948695c75bc3deaf4710029218f18e2ac2c79350cd52b02267a53d902ad481428a8d9f27148a194e0b4e4427b5481714808f6fad395453f6e4d285c50318579a917a52e053801400518a314b480690314d229f4dc500308e29b8a79a43400da61152114dc50322c531bad4c47ad31973401130c8a85d6a72314c619a62336e22cf6aa12a6d35b72c7bab3ee21c66ad3329c7a99f453997069b56643a9453696801c29d8c8a60a703400c3c1a917914c6eb4a879c5004a052114b4500308a6e2a434da005538a57e69b4a4f1400ca45eb4a6841cd004abd29d482945001452d140051494b40094b45140094b451400514514005145140051451400514514005252d140094d63d00a750837480500598d762014e56c9a0d46a7e638a00989c5279837629b82dd6936806801e4e68149da9c06050021a681cd3e917ad00380a72525387028011d82a926b2667df213576f25c26075359d400a2acdbae06eaaebd6ada9db1d2191ced9a829cfcb1a4a0425380a414b9a602e28a01a42d400b4bc53375293400b49ba9a5a92801fba8a65140176908a5a4a045393ef536a4987cf51d030a28a2802cc1f76a5a820a9e800a4a5a4a0028a28a00292968a004a4a5a4a004a28a28010d34d29a4a006bf4a8aa57e95150014b494a064d003d0735252a2f140a00314ffbab48a39a590e48a006fbd358d3db016a02680149a4a414b400a2973c52504d0019a7a0a8c73520e0500389c52af4a8c9c9a78381400acfc62999a427269a4d021c4d275a00cd38ae0503116a655a8875a941e298818d3a35c9c9a601b9aacaa8028010f151c8c0f4a257c0a8724f4a007a92c7029ce00181480ec5f7a89df3d280024e69c0e053052b702818a5a9a39a053d4520055cd3fa0a51802a366e78a0404e69338a4a00c9a60397de9705ba52e29ebc0a4323c05fad2726a42a49a72a63b500351314f341a722ee348a4858d32455e81001d2a28e3e957225a96cd121e89c74a9171e94abd3148c7d2a4a076ec29110939a74699393528403a5002629ea99a7a27ad498a0643b79a5400f5a711934d0319a400cbce4518a514b8a004c52629d4b8a0065358d3c8a4c5218cc52629e45348a0069149b69d8a0d00308a615a948a6e334010b0a898558718a898503222322aacd1e41ab64544eb914c4d18d71111cd5622b5ae1322b3a54c1ad13b98495990d28a4a2a881c2969b4e1cd00069075a5a43401329cad28a8a338353500211498a776a4a006d2529e94da0046a7474c6eb5247d2801e2968a2800a28a5a0028a28a0028a28a0028a28a0028a28a0028a28a0028a28a0028a28a0028a28a00434901fde8348e696dc12e2802e3734c8c7cc734e34a0d201d8a61eb4a4d373ce2980e1c9a7d118e295f81400d3c0a17eee683c8e299bb8da4500483ad293819a441802a2b893627d68028dcb9694d44294f2734e0b400463e6a9ddb0b8a8d4629d48644734952b014dc502194b9a7628db4002a16e94850eec55b8130b4dc0dc49a065461838a4a9186589a36d0223c52eda7e28a60331453a8a00b5494ea4c5022b5c7dea86ac5c8e01aaf40c28a28a009a03f3558aab11c355a14005253a9280128a5a4a0028a28a004a4a5a4a004a2969280129296928018fd2a2a95fa545400548829807352a8a00957a52519e29075a007e428a6e7279a69249a0f02801aed934d3413cd25002d029296800cd2529e9482801e839a91b005316909e68001d6958d252500140a4269568024518a0f26933c52e68014014f5e951679a914d3024501691e6ed4d278a88f26810162c6a48c6064d35569af21e82818b23e4d316933934ecf14805349d4d1d69c0628000314f06980e69cdc0a0042c49a693416cd20e4d0028e69e29a70052af4a0090539464d314548bc1e680245c28e6909cd3339a911734149081726ac429488956624a86cd12151318ab4981d69b1a7353041de914039a72c7934e0074153c630318a0062a548a9526ce295471408403de90814f2290f3400c02987ad4bc8a61e4d21898c518f4a53d2802818c3d78a5a7114805201b8a4a9314d22801a6908a71e949400dc52629d462900cc5348a908a61eb40c8daa361529f6a8de802034c352b0a8c8a0657917359d729835accbeb54ee63c8ab8b339ab992c3069b52cab8351568602d2834da5a007521a073462800079a9c1c8155ea443c5004a290d2034b400d3d29b4e34c34009dea551c544bc9a996801d45145002d145140051452d002514514005145140051451400514b4940051451400514514005145213c50031b93562d970b9a8106e6ab8abb4520148a4a78a6b706801a0d281cd1b7bd3905302451c50e32314abd2834011aaed18a5c0a5a33400d271542ee4dcc067a55c99f6a93598cdb989a005515228a8d2a5071400e141a4cd0290c43494a68c5000053957902815242b96a00987c9193ed50b7dcfad4d2f65a8263c8148060518a0e29a4d21a620245349a0d25301579a29ea38a290cb14514532486e07c9556adce32b55281851451400f8fef8ab83a5525fbc2ae03c0a005a4a5a4a0028a292800a28a280129294d36800a28a4a0029296928019274a8aa49299400e51520a62d4aa38a00052e3039a00ef48c78a0045eb492373499a6b1c9a004a28a4a005a5a4a28002734e14da51400f14dcd2e78a6d002e6909a4a28001c9a905305389a005349494b400a29c2900a71f9568010b533773484e690d0038b718a6668a2801c294520a506801c283483934f38a0068e2866cd231a4ed400500d349a51400f152274e698829c7da8024523b52d35454c899340d21628f3cd4e8b8a1531d2a4c0150d9aa43916adc4a02e6a08949ab6b80b48a1d18ef4e0326a34cb1e2adc08383d4d003e38863dea708476a5000e94e19f5a648d3f4a4038e0d39ba53474a0029314e1413ed48632998e4d3fbf4a6b7dee290c4141a0f5a701400da5c52914828189d29a69cdc536900d34638a70e682280198a4e94fc534d0034d308a7d21e290c8f14d6191521e698d4010b0a89bad4ed5130a0644454322e462ac1151482989993731e0d532306b5ae63c8cd66cab835a26612566454b49455103852a9c1a6d2d0007ad2a1e683c8a41c1a009a93340e4514008d4c3d29ed4c6a0054eb528a8e3a92801452d20a5a005a28a2800a5a4a2800a28a280168a28a004a2968a0028a4a5a004a29692800a2968a004a6b9e29c698793401240bcd5aa8a019e6a614803a0a69e4d29a4a0029e38a6a72d4fef4c072f4a0d2038e28cd0021a42694d46ed804d202ade483014554a7cafbdc9a68a603969c29a29f400a296928269005281481852861e940c5ab36e98e4d5653b980ab80ed8c9a43184ee727d2ab39cb13531f9633ef558afbd084048a42d40514b814c43092695464d29a17ad03264192051525b2ee71452290b9a4a28aa331920ca1aa67ad5e61c5526e18d031b451450028eb5713ee8aa62adc5f745003a8a28a002929692800a296928012929692801290d3a90d00251451401149d6983ad39ce4d22f5a009169e7818a6275a79eb400b9c0a631cd2939a69340084d3683494005145140051451400a29c05201c529e280034946692800a2929450028a5a4a514006281413499a00786a466cd368a005a6934134940053a9a29c280168a28cd0028e28cd266933400b9a426909a2801453947348053871400f14a064d341e6a645a063d12acc694c45e2ac20c0a96cb8a1c17028da58d2679a963e07bd41a13440018a79e480298b56618b27268026821c01c5590814f4c53101152ee27a8a621c28a074a5ed4c4212314d53938a5ea2917826801fd29a4e452e69ad9a43108cd47d4d4c0e0542077a06388029680334a6900d229314e341e680233498a7b0a68a062e314868cd252010d369e69b400d34d6a79a61a431b4d229e69a680226151b74a98d46c28022351b8a948e698e2802b4a995accb84c56bb74aa5751719ab8b2268ca614952483151d68602d2d20a51400e14d3c1a3bd2b73cd003e36a5a894f3529e80d0035cd309cd2bf5a68eb4012a74a78a629e29c0d003a969b4a28016968a2800a28a5a004a5a28a0028a28a0028a29680128a28a0028a28a0028a28a006b74a6c63e6c9a7374a10605202cc23e5a7e71d685185148467af4a6030c94824cf634eda29db680111589ce7152fdd5a40314b8cd004655b3907f0a177eee6a53c52500358e2aadd49b571eb561ce0567dc3ef90d2022a51494f514c000a7014a297228013148453f2314dcf3400a169718a414b4864902e5aa795ba28a6c03033481b7484fa52019707a2d434e91b7366999a602d213453698829e82980f3534432c290cbb651ff0011ed45588c7976c4e3b515172ec50a314b495a190847154a4e1cd5eaa738f9e819151451400b56a03f2554ab36e78a009a929d49400945145002514b494009451450025253a92801b41e94b4d6e94010b75a50293bd385003d7819a29b4b400b4c269c7a534d0034d252d250014b494b40051494b400e1413480f149400b45251400a052d2668cd002d2f414da526800cd25145002d0692909a0028140a5a00296928a005a290504d00145252d0014a28a2801453a9a29ea2801f1ae4d5a8d0922a18855b4e9499490e5181c54c385a8d453ea19aa10726ac229a62266acc6bd052287c31ee3f4abb12802a289368a9e3073409920a7ae29a053c28a621680062936fbd19e3140808e7da939cf146d38a55e0d030a3eb4ea4a0061e94c3d29e7bd18c8a00403229314f1c0a69a4310f3487a52d0450021f99698453fb62908a06369053b14948042299d2a4a6b0a0061a434e34da43131c53185494d34011e298c38a93148c38a40404531854b8a6b0a60576155e7194ab6e2abc838a684cc799304d57357ee93ad516eb5aa39da129692969885a28a2801075a990e548a869e879a0047eb4da730e69a6800069c188a68a5a007abf3528a81793530e9400f14b4dcd28a005a28a28016928a2800a28a5a0028a28a00292968a004c52d145001494b487a52018dc902a644f980f4a893e66ab10fde2680253c535ced14af518259b9a60286c9e9522d340a70e2801d4a293349e62838ef400e34d268c83cd358f148086e64db19acf3562e64dcd81d2a0c50020a7061498a9618f7b814c04dd8a4f307a54d71180703b557c5201dbc1ed4e04545453026dc28c8a880a70e2802612903029be6547cd1cd201f9a4a401a9706800a0d2ed3de9adc5301075ab16cbba402ab66afe9f1ee6dde952c68bd291e585f6a291be66028a8342851452d6a6421aa97230d56cd57ba1c034015a8a2968012a7b63cd4352c1f7e802d5252d2500149450680128a2968012929692800a4a5a4a004a63fdda7d3253c500434e14da51400fcd19c9a4145002934d268348680128a28a0029475a4a5140086945253850025145250014b45140051451400b45028a0028a4a2801334514a050028a28349400b49451400b4514500252d2528a005a2929475a007a8a900a620a980e690c7463156a3e82aba75ab510cd265c4957a539464d228a9e24cd41a12431e7156923c1a218fa54c17e6a00722f35300314ddb8a7af34c4380a5fa500734e3d38a0041ef4a00a41cd3bb50018a88801b352934dc530103678a0f5a36e3a0a5c5201b81de93b529a09e2801b9a2940a0d031a4734114514806e29c00a00cd078a06348a6d3cf4a6e290094d34fc534d00308a4c53f14845031845348cd3cd262900cc535aa42314c2334011114c352914c614015d8544e38353b0cd44cb4019f709906b3241835b532706b2a74c35691319a2bd145156662d145140052a9e69281400f7f5a653faafd2a3a00514b48296801c839a969918a931400829f480538500145145001452d25002d251499a0075148296800a2968a00292968a004a6b74a7531cf38a402c6a706acc2bb52a1507e502ace38c50031f9a1400295ba629a80f434c07a8a777a1451d4d002814d7407a8a78a0f2680230bb46054733610d4a4d52ba939da2802bb1c9c9a414502801c055cb64c296355506580ad0388e103da90ca52b1de735192295ce58d308a042134038a31498a603b7d1bcd2628c5003b79a5de4d300a5a0076e3eb464fad368a00764fad349a09a6e680141e6b6ac13cbb7c9ef5936d1f992a8f7ada957646ab51265c50e83e793228a96d130b9a2b33432a8a28adcc00d417032b539a8a71f21a00a545145002d3e3e1c5329c9c30a00bbda9294741450025253a9280128a28a004a29296801292968a0069a8a43529a864eb400ca70a4a5a0070e94da09a4a005a4345250014514500145145002d28a4a5a000f4a6d29349400b4514940052d252d002d149450014941a2800a70a414b40094514500145145002d251450014a2929d4005394734da7a839a0091054ca001cd31054948a1d18dc78ab7125476e99e6ad2ae38a86cd628722e6ad429514499357a350054943d06053d464d20a7a014c43a9ebd29b8e94f51c5310e078a4e94bd3a52633d680019a7734838a527028014e08a6f422973c534f5a005278a424f6a297140c6f38a0529e296801b8a31c52e29a4e0e2801290d3874a42314804cd0690d14001a4c629c4714da0606987ad498e29a6900d14879a53482801b453b149de801ac334da92908a4044c2a361c54c4534ad005661c544c38ab5b7351baf140ca52ad65dd46724d6c3a66a9dd47953549912573158734952ccb86a8ab530145148296800a28a4a00766928a2801452d20a51d6802541814fa45e94ea00052d25385002514b4b4009451450025145140052d252d002d1494b400628a5a4a4021a601b9e9ce70b4912f56a009e25cbe7b0a98d24436a0cd37cd05c28e4d00388a14529a5414c05038a3ee8cd3b14846473400d0723228a6852a783c529a00648db41359ae4bb1356aea4ed553340062942d14a0d2027b58f320a9ee9f834db7cac65aa19df27140c84f5a69a5a4a041494b4530128a5a4a0028cd149400b451494001a4a281d6802f69b1969723b568313238527a1aafa7af95116c75ab702ef7dc6b29335897221841452e3028a82cc3a28a2ba0e60a64832869f487a114019e783494e718634940c05380c119a407069ccfbb14016d0e5452d322fb829f4080d252d21a0625252d2500145252d0025141a28010d576e4d4edd2a03d68012968c52500068a292800a28a2800a28a2800a28a280168ed49450014514b4005253874a6d0014514b40051452500140a28a005a28a2800a28a2800a28a2800a283450028a5a414b400a2a541518a9a31486891454888588a6aae4e2ad42a32054b668913c4bb56a5519a68eb53c4bb8d41a12c2b56d718a8a35c0c54c05003c0e334a9d28038c53946298870f7a7814c191da9e298870f4a314a8bc64d291400d268a08e6947d2801bc9a46e2a420f6a6303de80117de9f498e28e940c420668c518c8a514009da9a4669c720d2e2801b8c0a43cd38f34c3d78a004a314b475a40266a3fe2a79a422818bda9a471476a3391400da4c53f6f14628019da931521a6d00348cd1d69d8e29bde900845348a79a4228110e2a375cd4c6a37a00ac57ad5796307357080454322d3030aee2dac6a89eb5b57916549c5644ab86ad118cb718296929453242929692800a51494a280169c832692a4885004829450296801714514a2800c514a28a004c518a5a280128c52d14009452d25000297145148028a5a434011bd4b10ce076a840dcf56e14e6818f99b6c248aa900ccb9356e5008c1a8827979239268112d48bd2a3439c54b4c009a6e734a690f1480435139c2934f26aa5e4855768ef4015646dee4d2014da70a602814f55c914d069c1b1480b60858c0aaae32c69dbc9a0d0322da68029c69bcd02176d1b69b9229ea8ccb9a00314dc52725b1484906980ec5262937526e3400ec534d264d250014f894bb8029957f4cb6f366c9e839a4f41a4682a18e0507d2addb458406ab3fcd28506b4106d402b16cd521ac0d14e6a2a4a30714529a415d273098a314b48680284c3121a6d4b7030f50d03168a28a00b76e72952e2a1b63f2d4dd681094869d486801b494a69281851452d00252019e2968e9400c93815054b29e2a2140052529a4a004a28a2800a28a2800a28a2800a28a2800a28a2800a28a280168a4a2800a5a28a004a28a4a005a28a280168a292800a28a2800a5a28a002814528a005a5029053c5002819ab118c0a8e35ab0178152cb487c2b9e6ad431f39a8a25e2adc5d2a19aa42a8f9aadc2b55e3196abb12f148a2555c54c80019a620cd4a053246914f4c518c9a7014c42e2940a4ef4f518a0070e94b8f4a414f14c426d1462947279a7500329a454869ac2818c0282296939cd20131410696909a0621ce294d19a693ce68014e29a697ad23102801a6931cd29a4348614868cd1400d2715097cb71524838a8029ce6802d21cad291447c2d06801b4700f34bda9a68101a69a334d622801739a4ed481a9ad2014001e2a17614924e05519ae707ad1625b2d3b0150338c55392f31dea07bb27b9aab0b98b339057ad645cae18d586b827bd5595b354886ee4340a28a648b49451400528a4a51400e153c6302a05eb565471400b452d1400528a28a005a28a2800a28a5a004a28a2800a28a2800a28a280169ac702969921e3148021196cd5d8c60555b75c915625620605031b2ca3cd0a29f8aa912979c9f4aba0714086aafa538961ef4f030290d3018189ed8a39c734bde909a40358e393542e5b71abcc030db9acfb8187228021a51494a2980f1522806a3029c38a431e460e29a4d2d048c50036956900e69f8c500376e4d5d8d008ff000aaf0a0693357252120fad2029469f3b1aaefcb9c55cc6c88fbd56db4c08b1462a42b4856988611494e34da000726b7b4d8bcbb7dd8e5ab16dd37caaa3b9adf23cb8d507a544997142c09ba5dc6af13c5436e98a98d62cd463514d90e0514018d4dcd2d2639ae939828a28a00a976304557ab7763e506aa503168a28a00b16c7b559aab6df7aad502034d34e34d3400d3494ea4a004a5a28a00290d2d21a06432d455249c9a8e8003451450025145140051451400514514005145140051452d00251452d002514b45001494b486800a4a5a2800a28a2800a28a2800a5a4a280168a051400528a4a701400a2a4514c5eb52a8a432685726a723040a2050a99a9225df254b35489635c28ab31af14c55a99454963a14e6ae46b9a822156d080281324518a78c5460e69e08e94c43875a900e39a60f514acc471d698878c76a334cc8000a5ce064d003b77bd381a8bcc14a2414089870696a1dddf34e1250325a438c5303d217cf5a005eb453030cf5a526818b4d3cd2335267d2801d8a6e79a01349de90c7521a4068279a00290f228a3140080714869d48690c69191516dc54d9c0a6d003e3fbb4c26824814dcd002e69188c521351e6810330c544ef8143b7cd551e42cdd78a044c66c753504b723a0e6a09e52381555dcd3136492dc1354e4918d399b348a84d510c84827ad2355af2b2298f162988a87351b12455875a88a9a044068a56183494c41451450014a292945003d064d591504439ab02800a28a5a0028a28a005145029680128a28a401451450014b4628a601452d25002544c77362a46e054680939a405bb65ef523a82a78a4830b18a93a8a00af045b324f5353818a3bd3874a005a6134eed4c3d6800351bb8009a731e2aa3bee7dbda8013cc751b8f7aad23ee6cd58b96c00a3b0aaa680014e5c520a915680018a5c8cd2eda365030cd21a522900c9a00169d4a129769ce28027b45ef525c9cb2a8ed525baed4cd419df2b3548c8ee1b002d43918a59496909a6d5084a42696986810d634da534828034b4680493ef3d14568ab8967c0e80e2a2d3a2f2ad738e5aa6b58be62dea6b293358ad0b8bc0a5268c1c534e6b32c82e64da84d155afdf0b8f5a2b48ad086f529d14b456c622521a776a4c50057ba194aa957a7198cd513d68185140a5a0092dcfef2ae0aa509c482af638a0414d34ea69a006d252d2500253a9052d03034c6e94ea434015dfad329cdd69b40051494500145145001494b49400b4514500145145001452d250014b494b40051452d0025252d2500145149400b49452d0014514b40051494b40051451400b4e14d029e2801f18a9906580a620c0a9e15cb5265a458030b8ab3026c4cf735022ee715717b0a83515453d4734e6c28a607e702802c2b015209474aaca09a0b8079a7611715f7548aeaa3dea8894d1e7e3bd02348cc3039e698d3e0f1cd67b5dece9cd4125d3b7f17e54c469b5c63ab014bf6a07bd6234add4d37cf2475a046d9ba41c961f9d34dea03f7b3586589ef4724707140cdcfb78ed4d1a8ae70c6b13cc7518e4d491ca31c8fce803792f11870d4f1720f420fe3583c7552452ac8738627eb4866e09f9f4a43727f8b8acaf3d9070d9152a4c58641fc2819a425cf7c8a707c30aa11c99e95287c8a405d2f83485ea0f33201a52fc0a00981a5049350a93520340c7d28a4cf145000690d079148690c4349484d19a000d309c53b34c63400d35196c538b735112334088a56eb9aaa7239ab12f26abc8326802bc9f3366a17524d5965a122cf5a7726c5610e6a748b8ab0b0d4a2218a570e5293263a546d11ad0f272738a3caf6a2e1ca667d98b76a46b5c0e95a9e50a8a4418a7cc1ca60dc47b4d57ad3bb8ba9acd6186ab4ccdab09451453242945140eb4013c638a9874a893a54a280171451450014b452d0014514500252d1452012968a5a004a5a28a601451da92900c90f151b1d91e7b9a73fcce053271f3003b0a0016e9d7152a5f7a8aa8453714c0d58aea39081deac03c566d843be4dc7a0ad2618a4021a6934a6a376daa58f4140115ccbb13dfb543072371fa9aaf2c864909edda80c40e0d001336e734ca775a4c114c072826a4518a883114e121a404a09f5a7027daa21229ea29e1d7d68188c79e9429146726945003f231c1a5846e7cd4479ab56a98c52044f2379701f5aaf9d9093de9f70dba409d854370d801452190eef5a320d26692a84389151353cd46f4c430d4d69179b3aafbd435ada3dbf594f4152dd90d2b97df088107a55ab68f082aac3fbd947a568a0016b066c86918a89c802a46355aea40b1134219997b26f931e9455763b98fbd15b23226a28a2accc4a28a2801b20ca1acd3d6b4d8641ace9061c8a006d145140c7c7c38ad01c8ace1c106afc67282810a4521a7534d0034d34d38d250020a5a28c503129add0d388a8e43c50041de90d3c0c9a69eb400da29692800a28a2800a28a2800a28a2800a28a28016928a2800a5a4a5a0028a28a004a28a4a0028a296800a28a280168a4a2800a753453a8012968a2801cb4f51cd316a6414863855b85702abc6b96ab6072052669144f02e7e6a9d396fa54608440295a4545a92c577249a747ef5584dce694484f4a622d3cb8e878a8448037ad45cb1e734f087b0a6224698f4c62a22e73d3f1a76c66ed4f10122802be49a4c73d6ae1b3622a27b471d28b8ac42578e4d342d3da0947638a548da80048f26a5fb3ee1d285caf5156e12a40a432888191ba54a2dc30ce306af18548eb48a98a570339a161c526d2463bd69345b8544d0807de8b8ca91820e0d4c136b54ad18e0e29c57207140118cab03daac29c1fad34c7f2d2a82147b500286c1a997b5451ae4e6a6070280245e29c05301a78f7a43241d2928cf14940013499a0d34d03034d34b48680109e2a291e9e4f150bf5a4005bbd44e493814e634ca00630a88ad4e69bb73401108f352ac7814fdb4e0b400dc0005382d2942453c0c0a40340a42b52629a680216150b8ab0d50bf5a00cfbb51b4d634bf7ab76e4650d61cff007cd6913198ca4a28ab205a51d69b4e5eb4013a74a905449d054a3a5003a8a4a5a005a5a6d2d002d1450280168a296900da5a2969809452d1400521e94b51c878a4024432c5bd2a3739626a65f9203ea6ab1a0621a6e2968a622cc173e4ae00a9d6f51c73c567b71c536901a86e131c1154ae67329da3ee8a8334f400d00340f6a7d481062976034011628db52f95418b140c80ad58484795923ad11c7ba400f4ab37036a617b0a00ce29cd014d3c8f514bf9d0020cd3813e940229463d6800a9526d83a547f88a5edd2801de602db8d35cee6cd271dc52003d6801303d293029f8f7a690680186a36a91ea1a042a8dcc00ae86d53c9b103b9ac5b188c93ad6f870711fb62a26cd20875a47d48e3356581c75a743185414371591a10953dd8d656af398f6a03c9ad67600135cdea3379d7271d0715505a932d84b762e68a9ad23c479ee68abb92912f7a2971456864251451400959f703f7a6b46a85d0c4940108a5a4a75030abb6fcc62a955cb5394c5004b4d34f229a6810c3494e34940c4a5a28a004350cb531a825a0062b629a7934e5230734c34005252d25001451450014514500145149400b451450014514b400514514001a4a53494009451450014b451400b4514500251451400a297b5253bb50025028a728a00720ab0a302a245e6a65049a4ca44b0ae066ac4232d935128c01528cf41506a87b312d85a3cbddf78e69e91e17dea54418e4d03191c407f0d3c47cf02a78d7db8a992304d0055584fa54cb011daad8833c8a9154a8e45022b2c6a064ad488887b54e3078229e2353d05004222046051e4e3b0a9fcbc74a5119ee6802b1854f5151b5a29e98aba63cd37cbdbd280281b523b52084af4ad02b9a694039a405500e280326ac1518e2a364140c4c530ae69e051de901194cd28518c5484526280136e45053e5a77414bd6980c55da28c12453f14628001c1a9148a6629c0628024a43d28141a062521a09e693140099a4341e290d218c635131a7bf5a8d8d00309a4a69340393cd210a064d3b1cd2539573d68015453c0a50314edbcd002638a074a7120544f2aaf39a0071a69a89ee93d6a26bc4140133d4125466ed49eb4d69c374340105d1e0d62cff007eb5ae5b2b5912fdead22633194514559014a2929680278fb54b50c55350028a5a414b400528a296800a28a280168a28a002969296800a28a2900544e373802a463819a8edf99371ed40c74dc00a3b55720d4ccdb989a4a0080d277a91e9856801add69294834801a620029ebc52aad3b6d200069e1aa334027d2819306a7035086a783da802d5b2ee258f6a59f18c1a7c402c43d4d569a4cb5218c2a0d34a734bb8519a62136538459a334a09a004309a6f966a50c69777a8a4041b4fad183e953e54f51408c1e8680201ee0d21f63560c47d698f190298151cf38a8e9eff007a9114b3803bd006ce8d0010b4ac3d855ab75dd3ee3da88c7d9ed2341d4f5a922655059ab17a9aad8bc1801c531b15545e46fc06c53cc8bb73b81fc6a6c55c86fe61140cded5cec63cc9bea6af6ad3991828e950594449dd8ad12b2336eecbb1a05500514e1cf1452288a8a5a6f7ad8c02945140a0421aa978391572aadd8c8068194e969296818b56ad0f51552acda1f9e802d1a69a71a69a0436929c692801b41a5a4a0634d4129e6ac1e955dfef50032929692800a4a28a00292969280168a28a004a28a2800a5a4a5a002968a4a005a28a4a002928a2800a5a2968012968a2800a4a5a4a002969296800a5ed494b4000152a0c531473528a431f18a9e35e6a38c7cb53c43352cb8a1c2ac429eb44516e22ad08c01526890cc67a0a9e345e06288d326ac471f22818e58c051c53d22e735201da9c3834080065e94f04e39a6e7da9c0f3400e55f5029ddb8a4078e683ed40850734e19ef4c079a70a005a42697a534d002633487a629d4c340c8c8c1e29ac29cd4c6348043494d2d499cd0324146299bb069eac2801714628cd02800c734b8a0528140005a7014a05380a60201474a76291973400c228c53f6d348a4031866a33c54adc0a89e819131a85cd48d55dcf34804279a01a6134f419a0091066a6504f4a6a00314f799625e7afa531126020c9aaf2dd2af0bc9a85e4926ea76ad5692786118ce4d3b12d9334b249df029be583d49cd527d4179c542d7e4f4a7ca2e64681451d8534843e959ad78e7b9a8cddb8a7ca2e7345910fa556954c7ca9e2ab7dacfad3bed05860d1617303cd9539aa5275a9e4393c540d54436368a28a620a5a4a5a0096135605558cfcd56c5001de96929450014b494b400b45251400b45145002d14502900514b486802399b0314282b096f5a8dfe696a698811aaf7c6681906fc75a03669b4601a00563e9498a304526ef5a00314f45a6839352afb5003b68005215cd39bb0a3a50033cbcd063c5482909a008f691da9635dce322a4c7142b60e690cb129da9f4154598935619b775a8da21da8021268cd3cc669361a04267de9c18d26dc76a2980e0c69c1e98339e29771cf22900fc8f4a50e3de99c1a36fa1a009436475a8a572075a4e6a195fb53023272dcd5ab084c938c76e6aa77adcd1e25485e461d7a6693d86b72d3a1600e7daa0bc1e544304e5aa7864f33231d0d50bf94b4d8cf038a845b16d6dc4b92ec42fa8a4bc46b570aad904669b0de185318045417372d3b64d5588b91b36f396a9629846b802a0e828c53b05cbd1ccbdfbd15561c33004d15362932d52114b45686425028a5c50021a82e9731d58c545703319a00cea283d6968189535b67cd1518a7c07120a00bc6929d4940869a4a53494009494b486801add2ab39cb55a6e9551bad030a6d3b1c536800a4a5a4a004a5a4a28016928a2800a28a280168a28a0028a28a0028a4a2800a5a28a00296928a005a4a28a0028a296800a28a28014528a414e1400e5152a0cd31054eab8148a4387402ad42878a8205dcd9ad1823a86cd6287c69814e19dd52014bb327a5496491ae7a54e808c53224c0cd4a0f34087a934ecd341a334087d28a8f3cd3835003f34a1a99ba8cd0049df34a0e6a3de0534ceabd5a98162931551af507439a6fdadd8fcaa4d005dc5348f7aa467b83d131f5a634b73fdd14016dbad44e0d56334fed4d37320eaa0d202739a696c5406f07f12915209124030690c7abd381a85860f14aaf8a064e0d381a881cd2838a009853d6a2439152ad31120a70a6a9a70a00314b8a701405a603714c6a9f6f1513ae29010bd42fd2a77aaf252195e4355a46e6ac49555fef500039353c4bcd448bcd4c5b62d021659446b81d6a8cb74b19dd21c9f4aa97f7a55caa9e6b359da56f98935a246729762fdcea6efc2703daa8bc8ee7934d65208a5c118aa336ee3706b434cb64b97d8c71543bd6a689c5c645005b934a8d3a66a85d59850715d04bc8acbbb3d4503305be56c528352ce837135105e6810e148c2a4111a1e3e2802b514ac306929882969296801cbd6ada72a2a98eb56626ec68024a5a296800a5a4a5a0028a28a005a2929690051451400b4d73819a5a8e6e5680238be79467a524af990fa54910da8cded55ca9a06381cd380151d3b38a007edfc6a3614e0d4ece68020a724854f34f2a0f4e29a23c9a0097ce048cd2efdc49a6bc1b1726a0e45005bcfcb42f26ab2c8454892e0d00583d298bd39a76f056980d218f14a4d301e682680241d28a6a9e29ebd2801871e949e58340396a7771401198d874a4218751538eb4f38c50054dc075a322a56456ed51984763400c6240e2a1639352ba941c9a849a621635dce05743b7c8b58e31c311cd64e990f9b72be80e4d6c38f3ae38e838a8932e286a8302173d319aca918bb927bd6aea8e12258c77acaed9a220c6fad315773d2b1a07099ef5640c90f3c530b9c50c734def401245d7345390628a405ea28a2ac80a28a2900b4c90654d3e9ac3208a00cb6e18d20a7cabb5cd3282829f19c30a6538751401a23ee8a0d227dc1f4a5a0436929d49400ded49de9c692801921f96aa77ab337ddaadde818b9e29b4b48680128a292800a28a2800a28a2800a5a4a28016928a2800a28a2800a5a4a5a0028a28a0028a28a0028a28a00296928a005a5a414b400538520a7a8a064882a751918a89179c559893240a965c5162de3c015790605430a600ab2071599a8ec715220e698054b18ef40c9074a5069ac7029a1a81128341351eea0b5201ead4ede3155cb8151493e0714016cca077a825bd54aa4cf249c0e052a42072dcd30253732cbc2f02858d8f2ec4d2798a82a37bc03a6053b09b2e46157185a9fce503b560c9a890786a864d4189eb5562398e89ee15476a85aed4f715cf35ec84673c5446edcf734585cc7426e14f714df314f7ae7d6e5c9ea6ac4734a31d714586a46ab006998c74e3e954bed4ca39a7ade03d6a6c52917126653cf22a70e18645514955ba1a991bd0d2b148b68f5266aba1cd4ca78a4326438a9d4e6aaa9e6ac20a009969e2a35a901a621e053853453c5300c546ebc66a5229ac32290151f9a85c75ab2cbcd4120a43294dd2ab63279ab538aaea3e6a00922150decbe5a60753d2ad20cd674f996ec83f747029a2599b756cfb7cc23835582e2ba3f2d5e02845503a5316c83c66b44ccdc4a28414da4542c30dc56d8d2414fe2ddf4a89b4a20f268b8b959921726b6f498362ef6e2a0fb108c82467153abb05daa38a571a897a79d146335977126f27152889dfae79a992cf3d452b94a264f90ce7914bf642bdab6feceaa3a5452a0c51cc3e4465a4783834d9a2207157447f3702a47837274a2e2e539f9460d475a1796a579c550c60d5a664d5829692969882a78ce40a82a784e45004e29c2980d3c5002d2514500145149400ea292941a005a4a7842466a3638a402e6a0762d263b5485c63de991aee928192bfc9001d33cd56a92e25cc9b7b0e2a3068000334b834a314ec500478a5c53c007a8a5d83b5004752dbaee7a8cab0edc55ab34c8cfad201d70008b07bd52299e9566f58f9981d00c5570deb400d0983d29c1452e78e29463bd301bb7de9a7729eb52e33d39a6b0f5a008fcd20f3522c831d6a365a8c8c5005c561b69fb86df7aa1b9877a7aca690ee5a5e4d3c7deaacb363ad4c928a00703f3e29c4f1512302c69cedc50028a5c0a6a74269720500417271c0aac393524cdb9cd1047e64807bd311b1a64620b67988e71c54da62b6e2efdf9a74abe55ac712f53d6a74020b2673d71c564d9aa466ea1279b7071d0702ab985c2e4838a327764f3cd5992e14a1c0ed8c5522599cff007b144870314e5c34b9ec2a39397ab20889e695065a918115340b9a0094c7f2668a7b9e828a4326c52e33451566625029681d6900514a4629a78a00cfba1fbd350d58bb1f3e6a0a0a0a075a296802fc27318a75456c731d4c45021a4521a75211c500328c52d1ba80209f81cd57a9ae0f3500a062d21a5a434009494b494005145140051451400514514005145140051451400b45252d00145251400b45145001451450014b494b400b4514a280140a951698839a9c0e80521a248973cd5bb74f9b3514698157608b03359b66d144e8b52a8a620a940a92c50335281814d45e69ec314086b1a68343b0c53370140c713814dce6a26971dea369b8a0095cfbd464ae79a81e7355e4b83da9a4265d322a8cf1504d78074aa124ec7bd57690b1aa488722d4b764f4355649d8f7a7c50990d3ee6dbcb40715443b94cb9342e49a314e43b581a648331c60f4a4a9de332fcc062a12083834c40a70c2ba3d3218e6806e515ce28cb0c5757a2c456dc12290d0cbad290c64a75acb92c9d3040e2ba97036d539625cd2291ce6c64ce3352c770475ad09add0b702a9cf6bb30477a93545ab79d5f1cf35750647158455e2e456869b7a243e5bf5ed52d1468aaf356a31c54207356a31814803a528a314b8c5301e29c0d479a5068025cd21a68a75004320aaee3ad5a90557619a4052957d6ab630d57651551979a00953ee9aacb07ef49f5ab119e314f4c66988548940e6a401063b5343629a5c1a604aceb8c64547200c3b531b69e94dda3d4d01611a1534df21454807bd18e690c55555ed4ee314d3f5a69703bd2006a85c669e5f77039a92380b60b0a0086283272454862e2ad88c018a0a500655c4018104560dedb189c91d2bac96307b5675e5b074208aa8bb1128dce6a96a4b888c52107a5462b4310a9203f35474e8ce1a988b42a4151f18a78e9400b451494005145140053a31b8d3334f81b26802c608150c8991c54dcd18a405097e51525b8e0b1ed4b7206ec77a78023b719eac681955d77127bd444153560d31973400c593d6a5041ef44106f7e7a0a59e2d8df29a0070346076351a6453b3400ec1abd028500f60326a94672e055c760901c9c16a4329ca773927bd4457d2a52b93c734cc628111f4a72b53b00f5a5f2fd0d3000c3e94b9e3d69a558751483f2a0071506a368e9f93466802065c75a9608378a1bf3ad0b38ba71486919b3c6637c5464102afdda069f8a86e620a1477c50055576534ff0038f7a695a4db4c4588e700734af20238aaa453d0127da8006e6afe910f9938247039aa2e076ad9d363305934adc13d2a64f41c56a5820cd76307e51c55e9615961d8dd2abd9a12371eb56198e31595cd4ce9b4fc7dd354ae2178d09238f5adcce473597ac4bb2df03ab1c554589ad0ca47c671de9bbb9c9a2da3dd963daa5741e95a199031dc7156615da326a158fe6cd59c8da05003add0cb263b5153db0dab454365a4252529a4cd6a738628a296801734d22968a0653bc038aa757ef0652a8d03168c50297340cb769f70d4f55ad0f5156281094d269f8a61a0069a294d34d00569cfcd510a7cbf7e982818b48694d250025252d14009452d140094514500145145001451450014514500145145001451450014b45140051451400b4514b400538520a7819a007c4b9356a3419a82318ab712e7150cd2289a1425856828c0c55781303353e6a0d47a75a99066aa349b5c015a3028600d201cab8148fd2a62b51b0a00a727b542d9cd5b74c9a634608a06532b93c531a327b55e58c019a4650698198f19c540d11c735a6e80f6a85e1cf6a62665b47cd0231e957da0e7814d16c4f6a772794863c2f4a965c4b1629df6639e94f4b76a77158c7922656e94cdbcd6f1b60c3e65a6a6989237029dc97133165c263150b8dc6b7df46455e73557fb314377345c5ca53d3ed0cf3a8c715d75ac4218828ec2b22de3fb2721706ac0bb761c7145c7ca684acbb79359d3cd82706a3796563d699e5b375a572946c30ca49a7c7213229640c076a72c0075a912302a6e595e5b76958900007b542b64d148181e41ad5551c549e58614862a1c815713eed5744e82ac81814084a5a6d3850310d00f34a692900f069c0f14c069453007e6a175e2a7c64546579a00a922e6aac8bcd68ba7155258e901594e0d483d6a323069c87b5003f04d053bd380f4a705cf5a6043834d248ed56f60c5208c668029e4fa51963d2ae18c76140885202984735225bb375ab6107a5380a008a38157b54c1453b146280136d2114fc53714010bad559d320d5d615048b401cf6a76f95c81c8ac8e95d4dd45bd4f15ce5d47e5cc4569166335d484f4a4ce29692accc78948a9e3981c035568cd00680604714553494ad4c9303d68025a2901047145002374a96d47538a898e0558b63f25004c050e76a66827150cf2009cf7a405550649496ee6a6b8e4800f4145b28ddb8f40334c76dc49a4323c9ef4a29695172c3de802d5b2009bbd6a09db3211569b11c581d85526e4f340c6e294520c83c5283cf2314c4489f29cd2dc3efc003802900c52f5a40421883528707ad23af1c543bb06802c7961ba1a42197b5351ea5590743400d5714a515874a71456ed4d64651f29a6046d1e3a530823ad38ca470c2986406801635dd28f6ad684797116359f68bb9f357aec94b5c0ea6a5948a718f327c9f5a8ee5f74a40e82a687e5899cf5c5546eb9ef4d098d383ed498a0e693b5310d35712ca54b613b2e10f4354c9abada8cad68b010368c73de80228a2f32402b6dcae228b042d67e98a1df711c0ad28c6f9012381d2b29334896d17cb418f4a6924d4a3914dd82b32c8f27d2b9fd626df71b076adfb83e5c4cde8335cc64dc5de7ae4d690ee4c8b30c252007d79a465c55b7c050076aacdc9ab208b6d2a82580a7ede29f6ea0c99f4a182264f971454c101e68acee696203494515b9cc14668a2801334b49450043707f766a8568ccbb90d671eb40c01a5a414b40c9ad8fcf8abb59f0ff00ac15a18a040c3029869d486801869a5b029c698fc29a00a721cb1a4141eb45031690d1450025145140052514500145145001451450014514500145145001451450014514b4005145140051452d0014b494b400a2a54151ad4cbc521a268c55d853a555856aec239a86cda28b0bf2ad4880b546055b823e054163a3b656219864d5c8976af14d8d78a93a50215aa32334b924d2e2981115a695e2a5c66936e4d0045b293ca153eda02d0040211e94792be95682f14852802af90b9e94a205f4a9ca5263140117d9d7d29cb6eb9e952834a1b14088dad948e285b52bcae2a5de282f4c081a19370cd45240f9c8156f7fbd359b345c2c5730b3a8ce2a31060d5acd308f5a0644500a6118e952b62a276029009403480e78a7471331a06488738ab512e714c8a1c55b4500502102e28c9a7e0628c500300a5c52e297140c6514add68a43014e14d14e0298870a0a734ab4ec6680212b50491e6ad115138a00cc95306a31c1abb3479aaaeb83480721a9579aae320d4c868026029c16914d3fb503136d18a70a7019a008f14b8a7edc518a603714b8a318a5140869a4c5388a4c50031aa17153b0a85fa50055953e5ae7f558b0fbb15d238e2b27548b74669adc992ba39f3494e230714dad4e70a28a2800a28a2801e9295a9d6406aa539588340165db356606db18aa4adbaac07c2802802ceecd55b8f99c0ec2a40fc7350e4c920f734864f8d96dc756a82accd228c27a0aacd83c8a0033c54f6ab97cf6155fa75abb6e36c59f5a4316e186dc55623d29d2b6e734d1400dc5029e30690afa502147b5386299d0e3a5283eb40c791c7ad57963ee2a6cd04e7af34010448e791c81479a0360f15a314612dcf1c9acf9e3fde13d2810f0f81907351b4ed9e6a22369e0d19cf5a6038c99a61c76a423d29a3ad0234b4e19651535fcb97082a2d3782ce7a28a88bf9b744fbd2289a56090aa9ef554804f1525c386908f4e2a3da4f434c434ae298f521257ad46e73408445cb53987200a23e054b6d1f9d3aafbd0c66b5941e55967bb55cb352c3e6ed50dccea8c902819c7e557ada3d91d61266a890018c521514b8348c702a4a3235c9fca80229e5f8fc2b334e8f2c5fd29dac4de75e6d1d178ab36b188e003a1ad568887b849d2abe0eea9a46e6a1271cd34488e4e31f854f6e9b793dea05cb3722ad4441c0a18d13ad14aab4566595692968ae93984a5a4cd2d0021a28a28011f95359920c39ad43d0d66ce3121a434305148296818e8ce1856903902b357a8ad1439414083bd21a5a0d30186a294e10d4cd55e73843480aa7ad1494b40c28a5a0d00368a5a4a002929692800a28a2800a28a2800a28a2800a28a2800a28a2800a5a28a0028a28a002969296800a51494e1400f5153469920d4718c9ab71ae3152cb8a258d70055b8862abc6326ad47d6b366c89e35ce2af42bc0aaf027ad5b4e0714864a0e2834d1d69d40851d290d19a434c0052a8a4033520140080669c1714a169c0500376d1b6a40bc501714c08ca8a63479a9c8f6a6e28020319c714d28d5648a4c62802b61876a39ef52b6699b73d6900ccd34be2a4f287a521857d281909940a63484f6ab0211e94e0800e28029fccdd01a55b766fbd56820cf4a9156802ba5b28ab0b18038a705c53d56800515201498c519c53017bd2d25148028cd21a502801319a314ea31400dc629452e2940a00502a45a60a78a0046150b8f4a99854445022bc8bd6a9cabed5a0f5564148654c5394e287182692802743c54ca7d6aac679c5585340c917ad3b38a60e69c2980ea318a052f53400945291cd14086e68a5c668c628023615138cd4ec2a171cd005792a85eaee8dbe95a320c66a94a85f2beb421339593873f5a654d74bb2775f4350d6a73b0a29697b5310da29692801296942e6908c50000e2a4597d6a2a5a009c49b8601ab566833b8f619aa310e6b4506c833d37521a209be6909a8fda9e7ad2633400a89b8fad5c90ec8f03b0aaa38e94e2c5860d2019bbd693750e38a8c12298132915229f5a801a787228025c06a46423a522b03c8a786f5e690c8fa7514e8d77c800e94fc2b0a96d23f9cb7a5202498ed5c74c0acd998fae6addd3f5f7ace7249a684c6139a052819a315420a4c60d2e2827d680278ee7cb8190643377a6db1c3163d866a1a0520250db8e7bd380239151a8a782463b8a005249ebcd46c39e2a6dca475e6a2232d40083a569e910e58c98e959c072056f5b2082cd09e0b1a993d0b8ad46a5b17be695f38cd6c6411c5568547522ac700562d9aa139aaf7927936eee4f419ab05ab1b5fb8db008c1e58fe9425760cc8b7533dcee6e79c9ad46181c556d321c2173deae3af1d6b47b905493ad46c7e5c53dfad319723dcd3247c4a3ad598954726ab28da40a9941240149948b5b8638a2a173b1324d1525101eb45556bc5ec29bf6cf6ae839ec5ca2a97db3da8fb59f4a02c5da2a87da9a93ed4f480d0c8acfb9c6fa3ed2e7bd46cc58e4d00369d494b40c2aec0e0c639aa549b88e868034438f5a0ba8ef59c5dbd4d26e3eb408bcd2afad413b82300d57c9a281853bb5010b74a0a15eb4000a0d1486800a28a53c0a006d252d25001451450014514500145145001451450014b451400514514005145140052d1450028a728c9a68a9231cd0327856ac2d4710a9d0566cd6289a21d2ae4280735040bd2adc75068588854eb51274a9939a043c514878a3ad3014518a169dd4d000a2a4038a455a78eb400e0b4b8a294530140a5c0a314b8a0069146d14ec521a00615a4c53e90d03232290ad4845262802223da908a9718a4db9a4045b7346da976d18a0646169c169f8a4c5000052f4a4a502801c29714da506988522929c4d3680131cd38518a5029000a29c0525002528a4cd19a0070a766999a506801fdaa3614ecd34d0044fd39aaac431e0d5c9177291eb59de43a4e4f383400922d45565d78a81d71480443835611b3557353c4d401623e3ad3fad314e45394e0d301dda954514a0f61400a4534d3893d29b40052134a699d0d0021a8a4e0d4a6a27eb4011b8cad53987a55d71c5549461a80399d4536dd37bd54ad2d5a3c4dbab3c004d6ab639e5b8da29c569314c901cd250692801ebd69c533d6a2c9a371f5a001860d252d0a326802c5aa6e651eb56ee9b6b041d00a65a2ed0587f08a85a42ec7775a431c0d3f15129c1a9873400741cd274a711eb4c6a4046e49a8c360e0d487dea32849e298120c1e94bc8a4f2d94645344a0f0d40128f6a5dc4547ee29777ad004c1c62aec7f241d79359abf330157e4902a81e8290cab74e338cd54c669d3bee734917279a620d94a062a70b9146ca008b6834c7423a73531434845022a9a01c54b220ed516314c09a3606a6d8a40ec6aa21c1ab28dc520239148ea3f1a13a52b9c9a00e281962c6113dcaa9e9d4d6f4ca06c51c8e959da4458dd21fc2b4a2f9db3e95949ea6914594e94b4aa005a41599623360735caeab39b9be201c853b457477f3082d6493d0715cbda219ae727d73570ee4c8d3806c8428a491ea43c0aaf21a68446e6913e66f614ec6549c74a130a2a891cbcb5584ce2a1887356178152cb432450dc1e9455798c9bc95e9451615ccaa29296b6320a5a4a5a0028a28a0028a28a005a5a4a2801c300534d2d34d002514525002d1494a280248df68a19b71c9a4403bd2b633c5003692948e3349400b4868a4a00292968a004a28a2800a28a2800a28a2800a5a4a5a0028a28a0028a28a0028a28a002969296801454d1f5a845588464d26345a897356634c9c54518016ad40b9e6b366e89a35da2ac463151a8a953ad48c9e3e953271512d3e801ec6945464d3c74a6028a7af5a8d79352a500381c53c520a70a60381a5a683cd3e80140cd3853453c530034c7e054bb68299a06561b89a976fcbd2a511802976e0500572a4502a561934d298e94808cad2631525211c500458a5a7114948625252d1400942d2d20a00752e29334a39a62171462814bde800c64d3b1c520a5cd2013a507814134c2680169293349400ea334dcd26ea00941a0d314fad3b2298011c544c2a563d29ac290159c54120e2adbad57916802ab0c53a33cd2bad34706802e47d2a5155e26c8a9d6801fd452639a338a5a601d6834639a280129a4734e6a4348061e0d4725484d46fd2818c63c55593926ac3540c3209a42317585f941ac6ce0d6eeae331d609eb5ac76309ee38b7349ba9b455103f20d34fb52514009452d25001524232d4cab16e99228027cb470f4fbd5573cd5cb927207651d2a99a432456a99781c5565eb5329c5004c1b23d2a37eb4ec8229872290119069d18c3734b8a9a24ce0d031f81e4127af6aa2cbcf4abd77f22aa8f4e6aa1a1031a9c539969318a72b6298875ba9df4e9a623229f1103a706a19e3c9c8a00acdc9a9a2045441486e455a41c0a00729c54830783c5331e9f95283da900fd8298c94f5381fe34641e0d00559538e2abb7079ad168f2b54a74c1a68086a6427150e29cac4502255e4d48064e053235c8ab96309927518a4d9491ab6b1f93046a4f26aec2808cd55652d32803e5157a21b54560cd50155c77a6e314f6a693804fa521989e219caa2420fdee4d57d3a0d91ef2396a835094ddea0de80ed1f4ad18d42c600f4ad365627a8c91b155d8e4d4f2f7a8913753421a5b11edee7ad34f40295bef93f950bc9a622586a6278c0a6c6b814d95f69a450c68dc720e68a8dae31de8a7626e6552d2515a198b45251400b466928a007668a6d28a00751451400521a5a43400da28a4a005a5cd368a007034a0d3694500389cd25145001494b4940051451400514514009452d25001452d250014b452d001451450025145140052d14500145028a005156adc722aa0eb576dc74a4ca8ee5c41d2aec430a2ab40b93575460564cdd0e518a952980714e51cd2027534fcd44b4f06801f4e278a683403939a604b1af152a8c5460e053d79a00900a5e9483ad3c734c000a70a4a506801c0734f039a6034f14c078a05341ed4e1400eed4a293b53939a621ac38a61e6a72b5195e690cae579cd2f6a90af5a611486308a6118a7b75c0a6d031b46697a534d2002714518cd1f5a0005381a4e9466810f069739a8f349ba80242d49baa324d3776280242c68dd51efcd2679a009334669a290eede3038a007d26297b50a093400bda940f5a76de28514c028238a9029229bb0f7a00818544e2ad3af15032f3480aaeb50e306adb2d5775e68004254e6acc6fbaa041c528f94e6802de2969b1b6e00d38d3016928cd266900534d2934da0069a6b52bb62a357dc0d03233d0d427eed4921c66a2278a4232b5419439ac62a0d6c6a4df29aca6503906b58ec613dc88c7e94c28454eaa5ba50c857ad51057c1a4a988a690280194529146280117922b46cd3e6dc7a019aa512e4e6b450f9507d78a4c6889e4dcc77544f16464548c035355b6f5e9486451c65dc2f7a9641e5b6d6ab16ea376e029b74bf3e0d00403a71cd19a02ede452e4375e2810019357605c62aac2bf3fa81577ee42cded8149948a77326f94fa541de866f98d28c114c42514639a5eb4c42834ede71cf229a07ad3b1c500200ac28518e9d298460f14d0e41a00b00e4f14ecf622a1470c2a40d48077d0fe140383cf14dce69c0e460f3400f0703d2a0b91915263d3f23514b9c60d0053a07269ce306917ef0a622d4630bcd6be931e11a523d8565c4a580add893c9b645e7dea24cd224b026f949356c271d4d436e31564b6056268458c77aa9a8ce6ded5dc119c6055c63581e209f2c90a9f734e2aec4ca7a6c26494c879c5699c8aab62de542171c9ab4c722adee495e4c9ef4b9f2e26f5230283cb532e890c107614d099176a7c6b839a8c67352a530262e1579aa53cf9279a7dcc811303ad5066dc734d21363d9f3454545512328a28a620a28a2800a28a31400528a4c1a502801d40a28140052114ea280233453881462801b4629d8a2801052d02968012968a4a0028a28a00292968a00292968a004a28a2800a05140eb400b4514bda80128a28a0028a28a0028a28a000506969a680157ad5eb7ed5457ad5eb73d2a5951dcd3b61c55a155adfeed5a51599b922529e0d354f34eeb400f14e14c14b9a0078eb8a931c5471f5a97d2801467152c7d2a207902a541c5004a29c0d3053c530177629e2a3a729e28024069c2994e5a603f34e14c1d6a41400a33d29c383480d3b8229887939151b0c734e03238a6be450030f34c3c53cf4a8cf0690d0c34d229e78a6b7348a18dd334d069cc38a6f4a401499a2909a0009a40d8a09a67534087eea3752014c3d6801e5b349d6900a7a8a60300e69c07b53c0a774a00600697a53b19a0ad20100269ea285069f8a602a8cd3954640a545a9a34c9a64b622a7e54c718abe9100bcf5aa970b8e4f140932b3f22a061539a85fad22c864155d96ad3540f4808d3ef53d87151a9f9aa46e9400b6cf862a6acd5146db38f7ab81b8a00534d2682690d0004d213c534b5216a006bd469c67de9e4d309e290c8a72322a16f6a7ca726a36385e68118daa3f38aa3110c793536a2fba623d2a90241ad96c73c9ea5d68c01946a8b0f9c63351891bb1a7adc38ebcd3245391d4546c3278a91ae77755a6acca0f4a008f61238a690475a98ccbdaa3660df5a0096d97730abb3f0428ec2a1b18fe7c9e839a2627cc24548c691e9475a40e1b83c1a7a26e900a065a81024609fad4331127239ab121db1d52dd86c8a006138e0d1523857194a873d8d022c5b951907bd4b732855080e7bd5453e943aeeebf9d031a7934838a7018ebcd2119a62141cd3b14dc539491d69007228fa53860d35971d2818d3cf5a6b27714ee68a6221c1078a943951f35490c7bde9f7b0ecc0029011a907a7229e0e3ad5621917229d1cf9e1850059520d0e383de998e3228dc40e6981526186a603cd3e6396a8c75a046b69a824916b6dc172a01e2b2b458c6d673f856d428339eb594f7358ec3922651f2b538ef3dc538b63a52673cd665913060092c302b9795cde6a25bb67f4aded62e3ecf64f8eadf28ac6d2e2ce5cf5ab8e8ae4b2e2c40107d295d8815213c543272714c048d803b8f6e6a076dec58f53cd4d2fcb073d58e07d2a02302a912c41d69c4ed524d30b605432cbc629d89b914f2176f6a8a97a9a704aa10d028a9963a2802ad39403450298876168f97d29b45003b23d28cfb5368a005cd19a4a2801681450280168a2928010d141a4340051494b400a28a28a0028a28a0028a28a0028a29680128a28a004a5a4a5a000d2a0e69b4f4a005614da79a6d0034d14514005145140051451400b4d34ea69a0051d6aedaf245521572d3ad26547735a1e315697a5538bb55b53c564cd878a766980f34f519eb40c5ce3a53d073cd3718a70c8a0090f045499e2980e69c0d0000fcf5323541df34e5273d6802d2d385460f029e0d301c29c29a0d04f1c5003b753d1b8a85324f352a8a06480d3d5a9829578a6224cfbd381a8f34ece6801e381c1a4fad341f5a76734c42364f5a888c9a90b678a6e06290c89873ed4d638e29e4e2a263939a4508c69a4d34d14804279a42694d34d0026722945005380a0431beb42d239c1a5539a604829c29839a781400f514f0b4d43532e2801a13da8d9df1530231ef48714010818a70148dd68ce05022543c8a9d48520fa5540d4e0e453116da738e6a095f775351efc9e69a4e39a0121ae6a17e69ee6a3a4318d50486a6738aab2be2900d1f7a9ecdc5402400f269af303d2818f8cee9c55ddd54ed4672c6ac66901216a6eea6134c2d4012139a4078e6a2df417cd003c9a8ddb146ea8e46c8a0061eb9aab7126d079a999b0b5977f2fca4034d2b93276466dc36e909f5a8a95b9a6f7ad8e7168269a4d25002934da28a0029f10cb532a6b75dcd814017636f2adcb63ef7151673562e005454f4aafb715231acbdc559b3cb649ed512f5a990ed5e2818eb96cfca0f4aac7f5a796249cd358647140112b156a90a875c8eb5191834e5e3a50200a41a78c1f6349b81386a08c503074e2a20d8383536ec0c1e950cab9e45003c75c8a7546990b96a7834085008e45216cf5a33814cc866a0078e69fb3e5cd3002bce38a5ddbb8140cb5611ee6cd497d8322ae3b54f611854c9aaeff00bcb92dd6a4657bb8808540ea6a89522b42edb3211d87155f6835484caeaec9d0d4be7061f352b45815038c5310d7396a1065852559b08bcdb855ed401b1608618579e0f6ad485946172371ed54963036283903d2af2c41803df1c1ac246a8908228ce052d4733848d98f4033525183e20b832dc2420fddea3de9d6919485462a829377a8173ce5b26b5fee81815a6da12318903a5314966c52cb2718a607d8858f6e69a15c8a77cca403c0e2a12d4a79058f5350b1ab48862bc95031c9a7134cc64d310e55cd4811bd29f0c66ad4687da95c69155720d157c47eaa28a571d8c4c514fde3d28de3d2ac819460d3f78f4146ff0061400dc1a369a76f349bcd00260d1b4d2ee349b8d0018c5028ce68a005a3140a2801a69294d36801d8a00148296801d81494514009452d2500145140a005a28a280128a28a0028a28a0000e6a4514d51cd4a07cb400d614c352374a88d002514b4940052d252d002514b450014d34ea69a005156ed4e185531d6addbf51498d6e6ac67a55a43c0aa711e055946e2b366e89853d4e4d46a734e0714864e7a669c3e6151a9cad3e2f4a00067a53c1e28dbce697a1a00074a51cd28c1a5031400f8db9c54ca6abe30722a456f5a604d9a5069b9c8a147340128a729a65028193034b9e298a734e06800a50c68c8a38a603b7d2eecf535193480d0224e94848c53734d6340c476a89b34f6a61e290c422984d3c9a6134804cd1499a728a040a3352638a169d8a00a9375a10f4a7dc018c9aae8fcd302d678a7a1cd42ad914f538a00981a915b02a00d4bbe802c87e290bd41e67bd30cbef4089cbd217e2abf9a29c1e80260c29775401e9cad4013669a58d34b534b500389a8d9b0282d8a864900a0047938aa33cd8a5b8b80a0f358f7174646c2f4a432d3dc8cd35652ec00e9552347735a36b6a78268197e0e1054b9a62fca00a375210e34c6a0bd30be6900dcf34a0d464f3466818f2d51b9a5351b9a62219db6ae6b12ee6dce79ad1bf976a11586e49626b48a319b066a6d0692accc28a28a0028a28a00056858c7f3027b73546319615a708d90337af02931a19349ba4269a0d4449ce69ca6901228c53c50bc8e2971e94008cb95c8a883e3ad4d9e2ab4a30722818e38268c53149a914834006011cd272a78e453f1498a00010c38e0fa534ae5b02948f4eb4fb71ba500f6a009a48479217be335446e8d881d3d2b524c146278cf02a9700e1ba7ad0819133065f43e9500241a9a6c6702a35c1eb4c44f1c9c60d3d5434cbb7a55700af4e95774f8f7be4d2634683b7916b9aab6ff0074b9fad4ba83e4a462a0958c70803a9a9286480375ea6ab9054d4a240dc743411eb5449096e2a07e7a54d28ee2ab934c432b4f4884b499e99e99acf452ee00ef5d1da5b793128239c76a993d0715764d6b03063bb9c1abeb90318a8add302a639ac59a89939e9599ae5cf956850757e2b499b02b97d6ae4cf77b17a271f8d38abb062e971614c87bf02aec8d8145a47e5dbaae39c54573d2ab764ec445b7b75a8e77ddf28fc6a3ddb4135121258926b4488b933b00302a066a19a9b9a620a912327a524699e6ac22907a5260872230153a640e4508ddb06a4054d4b65a4287f5a28205148660d14515a990514b8a314009452e28db4009452e3de9dc0e9400d028a52c4f7a4a005a2814b8a0040bb8e2acc3a74b37ddc540bc3022b634f908ef400c8bc3f23ae4c801a7b7874aae7cd1f956e41f745133718a62394bcb3fb2cbb3766a0922d8a0fad68eb3ff001ffb4fa0aa978ea7013b5202a1a4a0d140c281452d001451494005145140051451400f41528e9491e3cb3eb4e51c50035ba5447ad3da994009451450014514500145149400b4869c3a534f5a004ab56c79155aa680e0d26346ac55652a9c478156636e950cd91614d3e9829d9a928923a9d6ab29c1a9d58e05004b9a0d3339a70a0078f5a506983a528a009719e9499a40d4e18a0050d8152ab645434e5a6327068cd3334ab9cd00480d28348bcd2e2801e0f14669052e45002f5a4a33499a6029eb485b1484d3188a40231e69b9a09a6e6800269a6827bd46cfcd201f4f5a895b353229340122d3b04d39138a7eda6040f1ee1cd674f1989fdab60af150cf02c8bb5850066a4952896a09ad6488fc9c8a877483820d202e9940ef50cd7c910393555c48e3001a8bfb3e497ae6801b3eb2f9fdd8aa8daa5cb1eb5a09a3b771521d1891d29819b16a770a79e6b42df5557c07c834d3a5153d2a192c0a1a00d78ee15feeb0352abfbd61c692467826ad453b8eb480d5dfc534c80553f3c914c79f03ad005a79863ad51b9ba080e4d56b8bce30b544f9933739a00269da76c0e953dbd996c122a7b4b1e858568aa055c01480af0db2a0e9565700628a693400a5a984d04f15116c5301ec46690f4a83cce6acc6372e4d202024e69cbcd3a45c1a722f1400d22a190e2ac3f02aacbce680327547eddcd6666adea4dba7fa553ad96c73cb7128a28a64851451400514514013db47bdaaf5c385548bd0735059a1c834e9fe624f73486336e2803078a237cfcad4f2a474a402ab62a4073f5a88fa8eb42b6280246a8dd775296e2a4b48fcc9941e9d4d0322785e2c6076cd3323a7435a600925663d3fa5675c2665247ad20056f5a7546aa7a1a9402bf4f5a6021a9ecc00a58d40c3d2aedba00a8bf89a4c6865c9d800f6aaa5b1d7a54f3b65ce7a66abc89c6453426577e1bda90535f83480d32499413c6715a76404699cf22b36139f7f6ab00b05f949c1a4c6893ccf3ae18fe149338326d2781c5361658d49ef8aafe6649ddde8b0ee4aca3aad0b2e061b914c56c0c8e47a529dac33d28111cade87355c9c9a7b920d3546e38a605ed22dfcdb90c470bcd7411a967c0e9dea9697088adf3d3777ad5b78c6d045652669144a91e075a197dea4c60546f505156edbc981e42c3e519ae5a0469eef7373ce4d6cebd72238c443ab553d322c46643d4d5ad109ee5e5242f20551bc97276f4cd5d6359b70732163da9c77148ab3311f28a541b533eb51925dea563915a198c6e69b4b40e4d022781b8e957a22a5795e6aa4099c55d8d302a19712452a3b5282b48169718eb5250a151bd8d14d278e9450073f4a2adfd8c7ad3648553a75ad8c88283450680128a4a2800a28a4a005a2929450028a5a4a280147515a760f8715983ad5db47c11401d242d800fb53b3bb273d2a889c88b03ad324bd9238fe68f0a7f8aa89285fc9e75fc8c790062b3a43f39ab0d2032b39aac4e589a43233452bf5a6d218a29474a4a72f434009494b49400514525002d0393452a0cb0a00b491e20cfbe2931814fe91014c73c5004679a61a79e951d0014514ec71400c3494e34da005a28a2800a28a51400aab9a7a7cac29d1ae6a468f03348ab16a03f2d588ce2a940df2d5b4352cd225b4391520a82335206a82c9075a992ab86a950f228193f6a33c5349a7274f6a00721cd48a0d46839a9d4500467ad394d0e293e9408901cd28e2a21906a4dfc503240734a0d441a9dd680260dcd499cd571c53d4f14c0969ac6901a426810f14138a8c13413400a5a9a4e7ad04d46cd400e638a616c530b71504b2e2801f24b4918690f1d2a3890c8d93d2af46a00000a00745081d6ac280298b4e06802414b4c069435031f9a6b0cd26ee293750021407ad44d6e8474a9739a0d0042205cf4a9563503a52814739a042ed141c034bc1a69a0431c293d2ab4d1022ad303509068199b247b7b544c40ad36883531ad55bb52199124f8e141a818cb29ef5ba2c533d2a45b245e828030a2b07720b0abf0d8ac601239ad1f29547005358628020d800a43c548d4c639a432334c34f34d340119350cad52b900d579181269886a0dce2b490616aa5b27426ae160a28110372f8a9953005471aee93353918148082502a94cc0024f6ab931c564ea136c85bdf814d09bb2316e5f7ccc7dea2a527273462b639c6d14a692800a28a2800a720cb0a6d4d6eb96a00bd09d9093dcf150163d09a9a4f9542fb54152318eb839153452e461bf3a685cfd2a792dc2c008eb40c695a691eb4d8a523e56152b60fd28022cf6abd6abe5dbb3f76e0553085980ad061b4c710fe11fad263419f2a163ebc0acf9093cd5bbd6c0083eb54437342062e6a4490a8c1e4544463e94e1cd311222ef9005ad0036066f418154627d841c73523dc670b9eb48631c6739a80b14e0f22a7dc1aa295734d0990caa18645572306a56245309c8a648e8db9f7ab714808c371ef5408c54b1c9d9a802dba7d07bd44e9ea295652bd0e47a53f7a32e07e4681958868fdc529618c8a7b9001c1aacc79e28006393566c61f32603d6ab2a963c0ad8d2a03bf7301c7349bb21a5a9a91a85d883a0ad0886d500553830edbba62ada364562cd0909a8db8ea68393eb553519cc169237b7148673da9cdf6bd40aaf214ed15a1142238d40ec2b3b4c8bcdb832376e6b5cf3c55bec244126e553cd674e4aa1cf7ad2954b719aa17237385aa893220853e4c9148dc54ee446a16ab13935640d340ceea0d3e323bd004f0e715691dbd6a3859703a55a564c7f0d432d0d12103914be6fa8a7911b761485171c549434b8228a42831d68a0467195bd6a39189a66f3485b35b190941a28a006d14b8a4c5002514edb46d26801b4b4e5424d3dd0003068023a2971411400952c1214607b5458a70a00d58e62f803bd49753ef84c78c11daaa5b37ca07434f901404920f154229b9016a2e94d76c9a4cd48c18e4d36968a00053969b4e5eb400d3494add692800a28a5a0029f10cb532a68bb50058ea98f7a8e518353aa8db9a86634c0858d3475a0d2a0c9a40277a7ff0d348a71fb940119a434b41a004a28a2800a55a434ab4016a15a9f1915512509d6a41743348a4c7afc8d8ab511e055566070d5342e08a965a2e253c1a891aa50322a4d09579a917ad429c0a954f7a4326ea2963069aa7238a72641a00994e2a50c2a2033cd3d5680243c8a8c820d48282334086502948a3140c514ea6d28e2801fcd2e69bba8ce6980fdc6941cd34519a04389e29a5a909a631a00567a899a826a277a402492802a08c34cfed4d20cb26d1d2b4208846805003e18c28153a8a62d4800c5301c29734da4a00933403934c072696801c7a53452e690d03141a3348296810a29d482968017a8c52608a51c9a76280232091513715682d44f11a0083b500d3cc6698548a062d3835463ad38503b0add2a3714e660abc9aacf38e9486a2d8ac7151161504b3f5e6ab998fad162d40b4d2007ad42f301deabbcbc540ce4d3b0f9113493e7a51046f2be7b540a37381eb5ab0c7b6318a0892b0aaa10014a4123146d39a9513348cc218f033523f029e06054529c0a4052ba7c573daa4b99020ed5af79281939e057393b99242c6ae28ce6fa11d2f7a075a33cd686421a4a5a4a0028a28a002af59479619fad535196157e10c9116f5e29318939cb934c0734e63ba9a011d2901340bb980c558b860a801a6db0c2eea4b86c9c5032bede7a52336cfa53b8c52707834013d90124bbbf8579356233be42e7d7355a0221b77553f339c7e1567fd5db93ed8a4c68a7732ee989f7a85867914484939a4069885534f031c8e94cc03c8a7a360fb7a5003853d5038c11498ee29e8723d290018881907a74a8b39c8e9ea2ac9e548ef5524fbde8c2980c963e38aaec08ab60eefad4724608e2988ac0e297e9432e0d36988787228df4d27349400f2f9a68e4d36a58172690c9e08f915bb6d1ecb5ea06e1d4d65db47bdd40f5ad9233b625190460fb567265c5162d63c4633ce6adf40062990c5b540ec29e41accb2320fad617886e0e52007dcd6ec876a93e95ca4f21bcbf2dd89c7e14e2265bb087cb841ee6ad114d030a00ed4b4c6215c827b55055df2b31e8a6af4edb202df95548c148beb551264579d7355cf156656f4aa8df7ab433618c9a9235c1e45310f356a34c8a4c10a8ca3ad4a1929020c506315258ec8f5fd69727d4d45e57bf34c6571d0d2196496f5a2a0499d47ccb9a28119f451484d6a663a8a4a33400514945002d2e6928a005cd19a4068a007034b9e29b466800a33452d0028761d0d0d339182c69a69a68010d145250014a29296800a338a29280149cd252d250014b494b400a3ad4f12d42832d56621c8a009fa4755ee38c54d21f97deaac872d4c0653d0734ca7a9a403bad291f250a335214257da802a914869ce30691a801b452d2500291c5252f6a6d0029e56994f1cd30f5a009a2988f94f4ab7037359dd2acc12669329335633919a9d0d5480f15614e2a19b26585a72d46869ebd6a464c9c548a79a894f22a6140c9d3152afa54119a956811262929474a2801a69314e3cd2114000a5038a407069d918a06369bce723a53c8a50280014b4b8e29a73da810d6351924f4a7d21a0089aabcad81561eabb292d8a009ace20ab93d4d5be062ab83b14629449922802c034fddd2a00fcd3bcc1eb4c09339a5151071eb4ef3568026a518ef50f9cbea297ce5f5a07625a5eb55fce1eb4a2618a076658e051ed5079c29a6e0530e5659cd2839aa62e33de8fb47bd160e52f034a1c6ee6a97da33df9a6194f634ec3e5348caabdc540d720f00d506918d318bd161a8978dc2fad31ae01154b9cd216a2c528a2d79a0523cf8155b3c734c77c8c52b14a28596727bd40d27bd21c9eb4c3d6996358eea691c538f14d63c5032361519a73b546497e052249ad1774b9f4ad78fa0159d66a00ad18e93309ee4814548a05479e69e0d2205638154eea5daa6ac48f815937b360139e940333b519c05db9e4d651a92790cb2926a3ad52b1ceddc075a6d3870690f5a6212929692800a28a28026b75cb55e998246b18f4cd41651ee719e952ce433d21901caf229e843631498cd3a08ff7c093c77a405c1f247f4aaecd939a96561b719e6a0ce3ad0318e681cd0df7a9471408746fb4f34fb9b9de8a00e3bd4679a69140c69f51498a7818a36e391400d0769f6a9367714ca72b6c3cf4a007c6dcd4eaa3191501008c834f490a9a4048d9c7155a6049cd59cee1e87f9d31d723a5005556c903bd49d699e5e5f029ce7636d6eb4c064a991ef55ca906ae75a8dd45311580cf4a3152f96452ed0473408831cd5a89300542abf38157624ce2931a34348872e5d80e056a5a45be76661c839e3d3b556b684c56b8ce0b7a55fb20cb192c3e6359366a8b38029869c4d32a0650d5ae3c8b3739e4f02b134d8b73172338ab3afcfe64cb0aff000f27eb4eb251140a3a1aad90ba93edcf6a1532714e0454b181c9f4a4519f7dcb2460f7c9a8df01719a09df2b3fa9e2a297815a22195e635011cf35239e69a149ad0cc589413d6aec4a3155a2419c9ab7105e39a4c689420c52ec14ab8f5a76df435058cd8282833d29f83460d0044c8a7b514f239a28030a931cd49b69b83e95a9901a6d2e0d2aa96e00e6801b454be43e3ee9fca9be549fdd3f9500369314ff0029c7553f950636fee9a004180292839a2800a28cd19a005a767e5a6034e033400da434e618a69a004a4a5a4a00296814500149451400b4514500145145004b0f5ab28b839aaf08e455a27d2802399aabd492364d3680129c83269bdea58d78a00720152ffcb33510eb5315c459f5a605261cd237414f6eb4c6e6900da281450014da7525002a75a6c8b834bd2a4232b401052a36d348460d1401a56d267bd5d5358f6cf86c135a913023ad4346b165a4352039a810d4aa6a4d0b0a7153a1045565e453d1bb669016475a996abaf35321c5004ea78a776a8d48229d40084520195a5140e2801ac702ab473c86e8a32fcbdaad919148aa339c5003874a0706940c52d002d34d380a3140119a6eda94ae690ad0040e2a30993561969806280239785a855f9a9e55c8a8235273400e79420e6aa49a8283806ae35b193839c552b8d272f950c05343437fb4bdc521d473dc5579b4975e4138aa6f65321cae69948d4fb693de9eb744f7ac65f350f20d4cb311f7a99699aa2e18f7a7adc1c63359e8e0f7a941f434165c131c75a9036475aa6a7d4d48ae7a66802d06e3ad3d5866aa86f7a7ef0075a62b16d4823069f95503e5aa5bc6010c68699b1d4d02b170ba8ec2a36619eb50965318f5ce688fe5cb32e73d280b0e66a8d9b27349371511701739a0b4898b715131e73512cbc12698f2e7a522ec3d9fde99bb9a88be0f3480b1e80d0161e5f151bcbd875a70889fbd4e11014058802339e78152840831526314c63938a0968b36a2aeaf1552dd700559cf152ce696e3c1e69fbaa2434aed85cd2248ee24c0ac0d4e7c9da0fd6b42fa7d8a4e6b0a47323926aa28ce6fa1077a703cd211cd15a190a6987ad480641a630e6801b494b4940053907cc29b4f8fef50068c1b5216c8e48e2a2e49e69c4854080e7bd20a918639f7a774e940f9b8ee29f8cfd68022756cee0723b8a0f2bef52e38a825386a0622f269e3d0d33d187e34e073400a78a281d39a5a0036f1c5479c1c1a994d4732f71400b8e2908a646f8eb5275e4500354943ede952a10c6998140183914013edc1cf6a52dea7f1a6a4831cd4333e3a52027b54f326ce3bd25fc41ae4015674c4c26e351ffaeba66f7e281945dfc97dac38a770c32a7228bc5df3b1e9e955d498cd51259029aca00a58dc3f4e0fa53653c63bd00468b939abf651979140cf5aa90ae6b6b4a84ef2e470a2a64ca48d029bca807953c0abcab8007a552814b4bbe32bc9c9ef56cf9a3fba6b1658a6a395f646cdfdd19a52651fc0a7fe0559bad5cb4564ca46d2fc75a0663aeebbbe66639cb66b61506d008cd666931e32e475ad4069b0430c4bd854774c62b720672dc0ab2a326a95db97bad9fc29cd243642abb5471504d56a438154e520d691336557e2a2f308ab0c0639a89957b5684023b7ad4e8cdeb55c003bd48bf5a00bb1e4f7a9d51aa92311d1aa7491bd6a1a2d327d8feb46d7f7a68964c76a7095fd290c42afe94528998755a2803288a4c53b34d35b19098a9ed546fcfa54156ed46066802e647a538301d85459a28025ca9ec29b2608c6d14d068ea681109814ff0008a6bc09b4fca2ac6291802290cc47186229054970b895a9805003695724d2914aa39a0008c1a4a7375a6d0025252d250028a28a4a0028a28a005a28a5a004a3bd2d2a8c9a00b1101814f76da298bc718a6bf27da801a3934528e0521a004ab50001326ab01922aec6a3cac530223c135293fbaa8caf5a938f27de802991cd35862a423069b21a40462948a414eed40084714da7f6a68eb40098a729e08a3140e0d0046c29b53ba8ea2a1230680053b4e6afdb4b902b3ea485f6b52634ec6ca366a556c554864c815656a0d932c2354ebc1aa919c54ead48a2dc66a6539155236a9d5b9a43265e3a54a0d421877a786a00928a01e28a004dc053bb5464734f1d2810a0d3853334ecd003be945301e69f40052014e14500359722a22b539a69a00aee2991a60d4ecbcd228e6818f41c5481720535066a51c500412c6aca78aa935bfca381cd68b2e6a275e3a550d33265b55fe25a81ec636e86b6640a5b381d2ab4908072299a2665ff0067907e56a912ca503ae6ad9183522c98a0a28b5bca9c95a6807b835a85d405c8a8d95594eda632900d484b2f157638c3fa53123dcc475340ec575670381f9d0cd276c55a9a329b548a41092401d4f6340ec527f38d1fbe381935a11c6bbcab1e942460b29c64e738f6a0ab143c999fa920506d9ff89ab555049210005c76a68b6676381903bd033316d477635288500e16aeac0048cac064520849760076cd032898d188f940a3605ed52b28debcf19ed4fb955590853903bd032b1033c5253b6d31e810c738a6c4bb9e91b9381572da2c0ce293329bb22445c014e63814ec6298e6a4e563938a8ee24c2f5a7038159fa85c6d43eb4244b76336fe7f318a83c0aa8061a9f82fb8d2670466b4462ddc632f7a61e0d4eddf1d2a16fbd4c428e69ae38a51d686e4628023a29692800a9235cd300c9ab110f90e7a8a0066e2a704f4a991b70a85d73c8a589b0714865a1d8f7a93af3de98bc8a514863fad4170b902a7ebf5a475dc2802aa1c8a5036f3da9d3c261dbea466853b873400e1c8a29982838e94e06900e1d294d369c9f3b8028024fb3662e0726a9ee31bed35b51e36b13d1460567dc42ae4b0a10d918208c8a0039a604295229047bd3111c871506f2ce076a92638a8a005a500773408da46f22c37776e951c00a42edd0e383ef4978e37c700e8a289c948d147d4d228ac4efe1f86a85979c354cd8907bf6351139055f823a1a6490b29534a1cb119e68627a1a235cf34c0b96eaa4f2715b50c463b6001386359361179932afbd7411908f80c080318f7ace45a2c594222847bd4cded4d52c1474a0b1f41599606b97d76e0cf7c2153911f18f7ae8ae2610c2ee7a28cd725680dc5f173cf249a71ee266c5a46238147b54e298bc0c5394e5b148a44b85488b9e2b3a30647790f5635675190885634eac718151ffab8c714d032bdc7154646e6adce493cd529481cd6913291133530b529653de9a7156406ea3753714530240e6a55948aad9a50e45202dacec2a4170c3bd52129f4a7096958772f0b9e83b9a2a0b460f30cf41452b0ee4669b4a692b42000c9c56842bb500aa50a6e90015a6b1f1400da5c1a7eca5094011e2a548c914b1c45980abcb0ed028028184d2188e2b47cae7a714d31734ec0735a847e5cf8aab5adae4455d1b1c11593523169cbd69a29c28011a9b4e6a6d0021a4a5340a00292968a004a51494e1400514b8a280129f18f98537bd48831934012b35237dd0314d14efbc79a00681da90f5a5079a422801d18f9aadc6728c3daabc4b56222406cf714c036e17269a47cb4e727cac5349f9718a00818734c75e6a43cd31a9011e297b514a3a5004673483ef548e322a3a009314d618a900ca8348e334004672951b8a742d8241a5603a5005723140e2a423231dea3c62802e5b49d39ad08dc1158b1bed6ad0824c8152d17165f5353c6c0f5aa91b66a553506a8b6a706ac21c8aa6ad915346fb1b9e94865b53c73522104544ac08e29cbc1a064c0e0d3b34c0722941a043a9334945002eee69d9a8cf5a703c5002f7a729a68a7018a0078a75301a70a0028228a28018c29a29ed4da06394e2a407d698a334e1400e3484668a5ed4c08d941ea2a178719ef5671498a634ec673a11d453315a2f103daaacb6c472bf951734524576ce00a6670739a97a70c0d35a30466a8b4c6a3956041a3cc1e66724526dc76ce291701fe61c505227694b10fd4e702a513a193ee8c63bd531c2e067ad4b10574249c5328798b09bf3c9cd4b9cac000e9d6a150cc9f781c76a73ab204dc08cf4340c9fef4cbb5c0c0e6a7866508c14ff1727d6a8312aa0ae793c54e6611c6323e6eeb40873146b873d78cd0582307202e54f4a8a37db231930323a1a86590c87af02802073f3e45233163934374e29a0f1f35228573e955e56ec3ad3e47ec298884b7b9a04d8fb784b106afaaed5a4863dab4e6a839272bb1b51b9a79a89cf34198d95f647587752195cfa55fd425c47b475359a47c957146727d064630a698e38a78ed48d5466354678351c8bb4d4b8e3dc524fc8fd68020ef4e03229add053a23ce3b1a008c8c1a29cc39a6d003d17241ab2ebb5463ae2a2b71c8ab330f9491480ad9a695e7228e8d562140ea7238a06244f8383535567041e3a8a9a07dc307a8a404b52db47e74cabf9d463156acc79714929fa0a4511dda892e3d8553ba8fca231f5ab90e5dc93dcd417c41931e9c50808237120c1e0d21050f1d3d29b8c1c8e2a6560e307ad310d072323a54f6a06e2de950302a6ad411928147534864b23edb70bdcf26ab07e7144ee77fd2902ef4c8a040cb9e6a0938e47515283d8d412b60f14c445236e15369ea3ce0c7a2f3506ddfd3f2ab31fee6d1dbbb702980f89bcebc2c7a67f4a7cd36e94e7a74150da9d913b9eb8c0a6673d69012918e474a6b00c39eb4236383d0d248b8e41e298103e738ef5322fca2a25f9a419ab71a648a4c68d1d221081a56ec2b474e51331930727d69902c76f671ac833bba81572ca2f2a2c7239c8ac9b344582314c229c69ac702a4663f88ae3cbb55881f99cf23daa869316d42e7a93516b337da75228a7213e5ad1b78f644ab8e82a9e884b726152c2a09cfa5440548ee21b766279c7152514e46f32edc8e427029246247269d0aed8867a9e4d4531c7535484cad2b0e72726aa49863839c54d230ce29a8375688c990f971fa9a3cb8fb9abab0ab7502a392040785a770b15c4511fe2a43127634f3181da9bb053109e5ad218d682a29314084d829368a763de803de801f037979a29318ef4503128a4a335423434e8771dd5a3e5f35169710fb3061deaf85c0a622b88a97cb156026694c62810db68be7cd5a0a053614da2a4a0066dcd0101249a7d20e29818de218c7908de95ce5751afaeeb3e3b735cc54b1a014a3ad20a70a4311bad252b72d476a0061a283d68a0028a28a0029451428c9a00776c5252d235000396a93daa34e2a551cd003c0e294f038a5039e69ae7181400d51d69c064d0a7e534f51c66980f8c722a751cd43075e7d6a627e6a0435ce45376e738a7e3228888dcd9f4a60552304d31b9a908c934d618fca90c880a53f769691ba52013a8a8cf5a9139e298ff7a80268feee29319a212378cf4a1fe59303a50046ebb1b34a4e718a7c9f32fb8a8d7d28006191c75a8db9a90d31850032a7b7930715052a9c1cd006b44fc75a9d1ab3e1972055b8dea1a364cb6ad532366aa2b54eac31d79a92916d1b153ab55347e2a74348a2cab01d6a40735006cd39588340131340a6a9cf5a75021714d3914b9a538340081b34f06a3e94668025069c0d420e29e1c5004828a686cd2e680027340a4cd3979140c51c53c74a6629c2801483452e68a601462814a280108a695cd3e8c50041242ad555edc8271d2b44ad46eb4ca5268ce2bb4fcc29a63079156de3cf6a81a22872338a772d4880c654e4501f0dd29e5f69e7a51f2353344c6973b89c039a4677380093b7a035205e06471ea29760c532ae35e504039e94d795a46dd9e9d282bd78a0a8ed405c8d999f92734801a7a819a5206690ee46c2a32b8e4d48ec33d6a32c0f4a02e336e4d59b78b382692187772d56d46d18a96cc273be8808a6b0a7d3585231216a82438a9deaadc3614d344b32ee6432cc7d0546c3119a748bf313eb44c36c35a1832bb91b86290d3e6fb8871daa23d2801c0f34b228306e1d41c1a62b74a793f232fad00563f769abd69e47151d003cf5a691cd2e738a70e6802488ede6a52772f5a807029ea714801d2a5b66d8c4374228e18007ad0e367340c649f7feb4a87148fd79a4cf34013efc71deaf4a7cab58e3ef8c9acf40a5958f635335c7da2e71823152c68b308091963d866a84adbd89abf39d96ff00ef56713ce68436348a071c74f7a711e9d0d18a62151ccac158722ae893ca05b1c018aaf6e14365bad492ba81b3393d69010bb6e39a158a1f6ef51e369e3a5483e61ef4c059572370e86aac95386dbc1e951c8b93c53115c12a722a69253346abc0dbdaa32b4c070681133b148d57f1a1181a72b09170d50b2989f140129e3ad26f2060d3810cb9a89bad03258933cd5eb388bcaa0293cf355a1c102b674f8fcb85e5f6e2a64ca44d31124e8bfc20e2b4d5c6d1865aad68859c390381e9569947751f9564cb119bdea9dfdc8b7b49243d871f5ab2d1afa0ac0f125c61638077f98d095d819fa7a19ee4bb0cf3935b6bc551d1e2db0163fc55a000a24f51a1f1aee354dcbc9388d811dcd68448304838154e03be6926ec4e07d291448e36f00550b9ab92c98159f70f9aa89322b1eb534200ed50aaee35322b55999654ae3a50429ed4c08c7a53b0c3a8a4511bc6a7b540d166ad3061da9983e945c1a29b44693cbab6509ed4d286aae4d8aa23a6943eb564a7b546c314c9b11ed3eb453b3453023a6d1499aa1176d35092d8617047a1ab7fdb6723f762b1f340a046cff6e37fcf314e5d6e4760a918249ac5abba4c3e6dda0ec0f3401d545931a93d48e69d4018031453105277a5a6e39a6053d5137daca3fd9ae44f5aed2e537c320f5535c5b8c311ef498d00a5a68a7548c0f5a3b528e714ac3e4a008a8a5a280129579341a58c02dcd000c30714e41c6686e5a9474a0069eb487ad3b1498a00728e2a48f96031518eb56235e41f6a007b6370a85865e95db19a6a9e726800c55965090afa9aae3922ac4c70500f4a602c431cd3f1cd2c49fbb24fa535b893f0a621410aa7d699092e58f7c1a18704d25b753f4a008b1c13e94cce6a43901aa21d290080f348f40fbd4e7a43189c53641f353d7ad365fbd40029c114e7e4e69a074a9a44c479ef40119e2983ad3c824034d239a005230698c2a43c814d23228021231494f229878a009227da6af44f9159b562de4e706932933495aa50735594e466a446a8344cb68e7153c72738354d1aa457e6916682bd481ea946feb532b714865b5933d69d9c8aae8f5286a00901a33494734085cd2e69b45002d1452e28015734e0698334e14012014f14c5a7814000a78e94da51400b452d21a602d1494b400b4a29b4e1c5002d211914034b40c859306a364cf5ab4453714014248770aaef6eebcad6a347915194a65293465ef78fa834df3fdab49a307a8150c902b76a772d4ca666f7c5384bcd3dad8034cf20e78a2e57386ec739a8d893521869cb08145c5ce40b1339f4a9e3b655ebcd4ca9e953247eb488736c8d138a704c1a9b68029a452208cd46d53354468110b8e2a95dfddc55e7e6a95d6314e3b912d8cd9b8602a19ce40fad3dbe6909350cc7238ad0c48e462540f4a1bee0a1fa0a41ca60d0022f4a791f30f7a60a713c0f6a00632e320f6a84f06adb0c927d455561cd002548054629e0e08a007e38a01e314e0314d239a009a21de967f6a8d1ca9a567dfd690c46e501a45e47d284fbbb6914e185004ca7071eb5342aa936e3d4f151489b482bca9e94f56ca8f514864b7b282c114fddaab48ea44849ef40f7a0001c1c1fc2a41f374ea3ad34ae471d6915883ee2801e7da98ca5b0c386153100aee14cef9148068391fce97250822a455ddcd31f838a602300e32299d3834bf7791d29c5411914c444e950b0e6ac67b1a8dc67b502230769c8a97895307f0350914a84af22980818a1c1a7a7cc6890abae475a7c0b81486588220cc38eb5baca90451283e8707bd6758801c123a5694519b89c06e87f4aca4cb469db2858864734e6a5c051806984d41431ce01278ae3f5298deea4e54e573b57e95d1eaf71e458c8d9e48c0fa9ae6b4d8bccb90c7a0e6aa3a6a0cdd81024417a002a400669074a9614ded5250cbc93c9b5dabf7df8151a284882e31c5170de6dee3aac5c7e34d790d0045330cd675d3006ad4ec7154243b9eb48a224c7458ab71e2aac4bcd5a5c5362448314bc7ad3460fa52e054943b23d69bc7734605215140071eb4d6c5040a63e714c4452b85ef54de5c9a74ef938a83156919b63b79a29b8a29885cd14514c028a28a0070addf0ec192d29edc0ac25e4d757a34462b35c8fbdcd3405ea052e29714c436908a7e29a6988630cf1ed5c5de26cba917d18d76bdeb90d5a3d97f2fb9cd4b1a29d29a4a53486397a52c9f740a58c6691fad004745140eb400629c830334e20edcfad26302801075a70e94d15210020f5a0061a4a0d25004883bd4fbb6e31e951478c53ce02d00318e681c0a3ad394530248d32a3d6a5917f7c07a0a117914a1b370d9f4a62270bf27e1503af39ab05c7963eb5149c2f3e9401139f9692dcf2df4a29611cb6280223d0d3001b69e7be69839a4022fdfa25eb420f98d24a79a431625dd4970bb714e873b852dd0e9401029e455b2bb92abedfdd83ef536ee07b8a008bf87e8690f4a56fbc4536801c3a534f069471438ef400c6e698cb4f2714868022a721c1cd295e322905005e824c8c558159d1b6d357a160c054b469164c0d3d4e6998a01c54965946a991f1c55356a951a9145d0d8e454aafc55447ec6a653480b2adef4e57f5aae091d29e1a8026dd4a1aa306824f6a00941a5a8d5b34f06801c3ad3c53053875a4048b4e069a29c2980f1d2969052d0014521340a602d2e31482941e6801714519a28010e69d9a3ad28140c334829c05262800c714d2b4fa28021280d46d1f1c54e69a6802b344698d111daad1a4c73cd032af9649a72c7ea2a720500668018b1d3b6e0538521a0436929d8e2929011b0a8cad4cc2a36e940881c566de1e715a2e7ad665d1cbe2ae244f6283f535094c863ed9a9dc7ef1876c5307ddc7a8ab31209c602fb8cd31795a927ff5718ee062a1ed40003ce29f8cc67da983ad4883e661ed400e520a0f6aaf20a9e2c6769a64a3048a008945069e838a490739a0092239414f74046e15145532f248f6a008caf14d35263d691d7d2900c07069db41208a653a3eb8a065888f0637fc0d211b4e0f5a38c61bf3a7677ae0fde1486318647bd32a4208a859b6b8cf43401229a18771480e2a414008a78c8fc453986791d2908c1cad3979391f88a431f18e3dea09be57c1ef5631c020d4371864e7a8a622353d8f4a5e54fb5323f9b8279ed528e9834c43593209a88f5a981c7151c8bdc50044c377d69a3da958e0d267f3a6213196e2ad448dc0150c2bb9ab42da2dcea00ef52d9491a5636a0401e4efd315a3a7420296c77c7d6a14013cb423b7e15a10a6c418158b3415971dcd44c0ff007bf4a958d432b0442cdd0024d2039cf12dcee963b756ced1b9beb49a5c452dc36396e6b36673797ecffdf7fd2ba28502c6a07402ae5a2b096ac50d938c7e95690886d9a56ec2a10324536fdf11c7083d4e48f6a82caf0676176eac7269924996da3ad4d925703a0a84a22b163d69a02a5d36d5e4d5204673566f5f2d8155956b4464f72c215c75a99769ef55d13be2a50a3d050c68986d3de970bfdea871ed4bf85218fc0fef1a31ef4cfc292801f8c77a867240e0d38b5569989a68965663f31e690e290f5a2ac8168a1464d140052d18a314c028a28a007c640704f4aecaca48e4b58cc6c08c5717524771247f71d87d0d303b8a4c8cf26b8dfb75c7fcf67fce90dedc1ff96adf9d1711d9920771f9d34c918fe35fceb8c37731eb237e74df3e43d5cfe745c0eb9eea156c191463deb9cd71a37bd2d1b06040e45516766ea4d479a062e28a0529e9480721c534d28e94d3d6801294514a2801dd71448c0e00ed4014c032d400f51d295a8039a6b1e68010d0bc9a29545003c50d9a55148c39a00507029e9938a8cfa54ea3069889e3c8209ec29b1f37073dea5840239f4a8d0e25a604e57e5c5326c18c7b0a94739a8987c94015f3d29e9f2ee3498a463c91480898f5a8d7a9a933c1a8bf88d003e33c9a649d6950e334d6396a431f19c38a7dc722a35e1854b28cc79a008f1983f1a7a755a6e7f778a70ced522801b32e1ea3ab173c853ea2ab8a007118a4a5c714ccf634003ae47151a9e706a7eab91daa171ce45003c714d74c7229c872314e2b81cd004686ad42db48f4aab8da6acc5c8c50345e43914a56a0898a1c37e756970454346a9dc8b9069caf8eb4e65a611525132be6a78e4ed5483115223fad032fac8334f0d935511ea6571480b429473512be69e1a80251c5381e2a314ece2801e1a9ead510a7034013a9e29eb512b53c1cd0049466901a32280149a05266941a602d28a4340a0078a314829c28001d6968c52f6a0620a7520a28016928cd1400d229314e3cd262818c34da7914d2b400da5ed4a168340094518a319a0434d3714fc73486900c26a26a94d4327028115a5e86b2e761e61cd694ed85359121df29fad69133995ce4313ea29a410063bd3a4e1dfd0521398f22a8c886e0e531e955f7718ab046783deab37048a007034f46c366a3534a0d003b24353dbe6c533ad3d3961400f11fcb9a8997922ae48b88411558f50dde80234e08a957e563e94cdbce69ea33c1a005ebcd252a71914a05032bb03b8d3e31cd4e63cae69a13693480791b93dc5460907dc53a37e70695d33cd218fc89532061875150ce995cd2a9c7238229ce770cf7a008213b86d3d454c38a84232b6e152ac81f8030476a007ff2a55186dc3f2a6671c54d1f4a431723195fcaa39172bc53c8da72298e700e3bd005608c7240e9522b075f7156ed611e4b123802a86d2837f6a6225273c77a40d8e1ba5343061914673d698864a98e7b55763cd59638183d2ab37dea0459b5ad9d3e20d22b7a562db9c62ba0b51e5591751f3b0e335122e25e8899180e08cd5efba2aa69a8c22dce39ab6c7359b2c693595aedd79160e33f33fca2b50d72be249fccbb5894f083f5a715760caba5c2649b763a56d8dea38008aaba6c3e5dbae7a9e6ae8e9449dd82449012ce3208c75aac4f9d7723f500e054ef288a0600fce471496a234846fc926a4a1a4003ad549db19abf24aa461540f7359d747e52735484ca6c0337352240a4d400e4d5888803ad599932db8c70697ecffed8a5564ee697747ea691430c047fcb4149e49fef8a79741d3349bd68019e51fef8a4f2ff00dba7975a63483d28110ba12c155b24d2de40b0aa83cb11cd59b08bcdb8de470bcd41a9bee98d342667328e293682694f2695473564162de1048cd153c04280714562dea050c52629d8a315d021b494ec51486368a5c52628012968c51400945145001de93bd277a75000052e38a555c8a7a2f6a00691814c3d6a79138cd438f9a801314a3b52d397b5000dc29a8d7ad3a4eb40e050014d34fed4d22801b52a8a8c0c9a954605004980ab4c7c0352632054329f9a801d18dce2a4ef4c854e734f1d6988b36edc9a6aff00adfa525b71b9bd4d206c3734c0b0872c6890621f7cd245cb8a74fc45f8d0055078a69c96a453cd3dc60f148080f5a61eb5281904d45de90c05277a51d690d002e79153b7fa935077a958e621f4a008873527fcb3a6272714f73851400e9326207d2a1c559550f1907d2a0a002319e0d4722ed6f6a78e1a890829ef400c46c535c73499a7755f7a006a9c54c3e65a83bd491bf6a0090286e0f5a7463078a43d030a5cf391401641c8a960906706ababf149bc8606934527634f68229a529b6f2ee1cd4f8cd666c8ac529318ab0c98a8cad0318ac454a925464520e29017124e2a656aa0ae454c925005d56c54b9c8aa6af9a915e802c834e06a10f914f0d4013a9069e2ab86a7abd004e0f14b9a895a9e0d003bb528c8a6034fa007528a6834a2980e14e14d14e06801d4b494bde81852d18a08a004c668029c071487ad002629a7ad38f34dc500252629dde928189494b8a314084a31475a42690094d6f5a7134c63c500358f155a56a99c802aaca734c454bc936a1acb898b4c71eb8ab7a849918154acc61d49e84d69146127a8d91487607d69a384c54b38f98d461723354491bf183ef55ee171213eb5664ee2a1b8e514d202b834f539a652a9c1a0093f8b029c870c2a36f9581a901f9beb401755b7c5b476aaec314b0bed600f1cd4f74a0a6e51c50040a3701eb4de8d4f042ae73cd46645cd0038726a48f05b06a28c86ef532000f5ed4013a28da73e951baeee943be1073d453e0e4e4f6e690ca4c30c477153c6c1d707ad3265cc8585314956c8a432764ee29847a54f1b075cd47b774c00a404f147f200475aa13c66398b27ad6afdc8989ec3159ce72c7340c443e60f7a9d46d18351a2670c3823ad4dc11ef4084cf350b0cb851dcd484f1496ea649b3f85032eb8f2ecb1ddce2a95c205b7c55cb96ccc107441cfd6abdd60e17d2840ccd0769a994861c5248986e698418ce455122b9e306ab9eb5348e1c022a3c50226b542f2aa8ee715d2ed52122230140231593a25b8927dcc32abcd6b590796e59f05901c8c56722e269c5f2a8c7a52939a6ef07b30fa8a322b33423b897c9899ce00504926b8d42d797f96e4b366b7fc4575e559794a7e6978fc2b2b4787e73291ec2ae3a2b89ee6b2a6c50053954934bda9c871cd41456bb41e7a2a9e48cb54b8c0a817cc9a7778c64e7009ed4f68643feb25c7b2d3012595178279aaae6396360490e0f00f4353ba4718240c9f5359cd71fbc3f266aa288930d9838153469d2a232720afa502494f45354496c47414155d4cc7a21fce9e0cbdd7f5a4324d80d1e58a41bc75029c0b7a0a43186314d3166a6e69d0c6649557f3a00b36b0f91684e3e66acabf1f356dce70028e958b7e46faa44b286c352c31e4f22a32c49ab56cb9229c9d9104e8a028f968ab48102f345637031f1498a7628c575086629314fa4a006e2908a75211400d34629d8a3148637148453f1487a500474e419a4ed4f87938a0091076c5380c71de9d18c1c1f5c53b6ee662bd8d30229b815101919a9271f350170829011e38a72f4a0f4c51d050031b96a314b8e695464d0026290f5a7e0534f5a00555e69c4e30284a073264f6a0094103a76155e420bf1562420293557ab5004f11c29cfa7152018407bd46385e2a45e5698896d864e3a0a52bfbc14db7ff00594e270d4c05071253ee384eb517f1d2dc7dc5c1eb4015c548c3039a60e94aedd3e9480637087dea11d69ee78a68eb48603ad2529e29b9a0071a993062c54069f19e2801070d4b27dd14c6e24a999434591d6801f09c81f4a81ce2422a580fca2a193efe68014f4cd21e569c395c5340c1c500439c1a729e69251f35354d002b70d4aa4523525005853f9528f4a8549c54aa41a00954f148c462905364e08a00b56927383d6b523e56b06372b203dab6ed250700f7a892368326db4c31f7c55af2f34c3191c8a82caac95195e6adeda6bc74015314b52b474c2b8a062ab9152a4955fa500906802eac95209306a887a7ac9cd00682b8229cad8354964a9049408b81ea557aa6b253d64c5005a069e0d575929c1e9816334e535107e29c1a802514a0d460d381a00941a5cd460d3b340c901e29698a69c0d002d146ea426800a4a338a6e734001a2826933400941345349a00526987ad2b714dcd20034c634a4d42edda810d739aa73c817bd4b3c9b41acb9e6ded807a55455c993b105d36e634c830063d29263ce29d18f947ad6a6013e011ef51e7031ed4f9bef546064f34011b72298e33195f4a9586141a61e47e18a00a67ad253a45dac69b48077514f1f773e951834f5f4a00950ee606aeb1cc231f4ace56da6adc6c5a361edc50046df34648f5c5438da79a9607c646383d4532541d474a008812a700d486523906a37fbca7da948cae7d2802512965e69d1dc95047ad408d8068cf21877a00945c8c924668f39376474a81c7269829017a39d50e4743535bc886424b01f5acd073c5349345877356eef54218e3e7d4d67f98c4e4d440d3ba0a2c172513b2b641ab48fe627ca70c3a567e6a489ca1041a2c172df9a194f623a8ab7608154b9ec3359ec048caea707f885686e096a141e5f8a9634247f333487bf26a076f30e477ab27f7717d6aa38d9cafdd3d3da843620f9be53f85444804ab53d8e791d6a295b70e7ad51245b72fc74a902510ae4126ad59c267b8541c64f5a4068e9e861b238e1a43806b534f8bca8c90393d6a9cd0925618cf2b8c115ac88150020e477ac9b3442d35a9d9aaf7938b7b692438f9466a46733af4df68d4bcb5e427ca3eb57ece0f2a055ac8b206e2fbcc73939dc6b7810178ab969a021854a9c863448e63b7662792302918e33cd57b87dfe5ae7823711e95236cb16df246067ad48c41aa825e703b7156922665dcd855f5269d82e54bb7db19c5670ab77f22e76a9ce3bd520dcd5c5686727a93c6b56117d05411b8a9d1f9a1822551c74a00f6a0c99e829bbcd218f03d69702a2de69771a4325e2ad5947d5cfe1545496600569ffab8801d7140c8a639cb7a562defdead5b87c00bf89ac7b96dce69a264408809abb047d306aa20e6adc41b1c51233272a71d68a692d8a2a1211468a28aea01292968a40368c53a8a00662940a7628a004c531f81525324e940119fb94b11c64d349cd03814865d500286269d19e5b1dcd4717318a987a8e38a622bcc3e6a0fdc0286e64a56fbb4010f7a73f1814d3d68e73d690c5028230334eed437402980dc7028c529e4d388c27bd002630b420279a3b519c600a0074c7b541e95249d33518ed48097b003bd587508a07b5428bb9947bd589be634c4311b6cc053dcfef3ad447fd7d48ff7c530164ea29b2b64014f9800171cf15130f9770ed4806669cc06dcd33352e330934015dba5317ad39ba535690c56eb4d14e7eb4d14001a7c7d298d4b19a001fef8ab117dd23daabc87e6153c2d81c5002443e6fc69932812b63d69e80ee6e29b2fdea00129241c834253cae6802bca2a2ef5624191c540c3068016928a0500394d394e1a980e28a009c1c1a749ca8cd448c31cd38b718a004f4ad3b19372007a8acadddaac59cdb2500f434995176674d6ed9519a98a7e22aa59bee18abebe86b2372b3c58e4526ce2ae6c0474a89a22a78e86802a327b54463abcc9ea2a368e81945a3a614c55e64c0e95134540153149922ac3c78ed4c298a00607a72c94d2b49b68027592a512d53c9a50e6802fa49532bd672c952acd401a08fcd4a0d504987ad584973408b4ad4e06a057a915e802656a5cd45ba9435004a0d3d5aa1cd3836298c9b3485a981f3466801dbb9a01a8f34b9cd003b83499a4a40680149a69a5cd34b5002934c66a697a63b814840cf55a59719344b3015917fa8aae550e5a9a5713761f7b77fc2a79ef5561e739ef55236677dcc724d5e847402b54ac60ddc8e61f313ed4f847eec532e010fed8a9138503daa8431b96a6e3e6cfa549d18835121f9ce681060321c54001dc454ca0066a4906d7571480a970bce6a0abb749c823a1aaa5690c60a7a9a67434a0d003cf0d56236dbd2a0eab9a910e40f6a007b2853c77e69927caa7de9d29063040e56a391b283140119194c8ed4f8be6cafa8a6c07e7da7a3706957f7727b0a006afdec1a52b804679148fc499fc6964ebbbd450007e6507daa23d6a4c9007b5466800cd291c669179a71fba050022f5a18d28185a677a005a5cd251400a1c8e86a55b8618e738a882934a16802e9bdf31406ed4aae1863b1aa54a1caf434ac3b965b287155e4396e29de7ee5c1ed4d1cb5004f1290a2b5b498b66f9987dd159b103c62b7154c1628aa06f63c8f6a891489ed6065b9decc4e7919ed5a04e6ab5ba798a243904d4a50fa9acd963eb0bc4d75b6dd2053cb9c9fa56c1538ea6b93d5e6fb56a4c14e42fca29c77063f4788fcce475ad5fa5416917930aafb54ff4a4ddd8d21ac9fbb773d856607c9249e7a56a5e49e5d9103ef3f02b39a2000aa44b1a1c8a735c10bc93814c2a45412838354892196e3731a60979a3cbf6a360f4ab2478b9c74a70bc3ef51845ee29c234f4a404a2f7d49a517abdf7535228f3d0548b1444fdd140c417c83b35385fa7f74d4a9043fdc5a996087fb8b5250ed36459e6ce080b5a124833d7a5538d427dc007d297ea6a4643753e149c124fa566bee3c9435ac466a1940029a6268ce5273c8ab5137b1a8580ddc54b11c53666c9fa8a29375149220a9494515b94251451400514514802814514001a8a43529a864eb400ca052528a432d407a0f41538c85aad075fc6ae38200fa53115c0f9b34f908f2c7ad29000a8e539a00871b9a8c7cd814ee82953d681863a0a1fad3f19351e7ad000bc1a4279c52819146df9b9a0053d293b8a56e0533bd0039f914c51935201c134c8fef1a00b1120dde952138700723151a101bad4871e60c502221febaa497fd666980e6e73ea6a4947ef88f7a60364fbb9a8f7e63c5492f0b512e0c648a403474a9031f248a881c0a9139434010c9f76a35a925e951ad218e639c536958d250029a13ad250a6801d2f5a9213c0a64a39a747c0140136409091dea39b865f7a767914b380554814011af5a9d578cd468bdeac478298a60547187f63513af5f6ab2ebcf35162802b1e940a748b834ca403852d20a776a00414e1c902900cd28383400acb83834d562ad9a576dc734dcd006fe93719c735ba803af1d6b93d358ab8c1ae9a07c2823a564cde2ee8b014a9c1fce948c8e6941c8a55209da7ad2288f00f0474a6b47e95332118228da0f5140158c751347575a3e2a22a68194d938e95194f6abacb51f960d005268fda9a63c0abad18a89a2a00a6529a50d5a68f8a618e802be31402454cd1934c319a0016422a549b9eb506da4c11401a11cfef53a4c09e2b243b0a912723ad006b093d69eafef598b720f7a992707a1a00d057cf7a76eaa4b2e7a1a904d4c0b5ba9c1f8aa82614a26a04592fcd01f8aade6d024e3ad00592fc53735079c291a70071401397a63498aa8f76077aab36a51a0e5a8b0ae68349ef54ae2f163049602b22eb596ce23159b2dcc931cb1355ca4b9a342f75367c88c9fad672e5ce49c9351d5985322a92326ee58b65ab7037ef48f415144bb1413440d995d87a62a844930cb8cd4ad80463b0c546e774a0549b72e47a5310c93895c557fbb291ed5624ff005a49ee2abb7375edb73400808dd52c8a1a31f4c531930734f63851480ad37fabfa54498619c558913703f4aab1fcb91fdd340c8a45c3536a79c679a82900e43daa48cf241a841c1a9012082280274ebb7fbc3155db206d3d8d585f9864751493c79f9bd6802ae7069e4e79f5a630c1a70394c1ed4003e782690b6540f4a7b8cc63daa2a007f58f3e9519a907fabfa9a61a0058fef53f1c8a6270c2a62b834011c9e94cc53e4fbd4ca00314e55f5a551c73d69680169a48a42d8e94deb40016a4cd1450014f57c5328a00d3d3e5479d15c81cf735b91933dced1caa9c0ae441c1c8ad4d2f55fb34aa26cb47ce71512452675caa15401462a282e239d03c4c1811daa526b2342aea3702dace593d178fad729a747e75cef6e71cd69f896efe54b75ea796fa76a874984ac0188fbdcd56c83a9a2bd05395371a4553d2a4661140cc78c0cd414675ecbfe92887255067f1349f7c642903dea5b54692332b72cc7bd3d93d6a93158a2ea7383c0f6a8656dbd067eb57dd060e45567b8893831063eb548868a2d21fee8fca9a0927a55a6bb8b3ff001ee9482e90f4854559257c1f4a36b559fb4a9ff966bf9506eb3fc09ff7cd0057018539770a7fda0fa0fca98d39c7ff005a801e1daa5473550ccd4a276f7a560b9a28fc734ede2a8a5ce17054d1f6824f029728f98be5862a37c1155bcf3486527ad160e607500f14b18a88924d3973eb4ec432c8e945460f14504905251456a30a28a2800a28a29000a28a2800a81fbd4c7819a818e680194e07914da51d690cb307dfe3b9abf2f61e82a95a7fad527a0e6ae3b6e9723a534222da73f4a85b96ab6ff2a9cf5a8157b91da9810b8c814f51da80013cf4a01f9a9004848438a8d41d99a966e140f5a461c0140020c0a50b939a451c52e70280237e5a9afc1c53d14b37d2a36f9a5a063c118e69abc53b6d21e08a009429201f5a09c494e404b28ed49b4b4b4c4101ccbee0d4f2f0ec6ab41feb88a9e5c9739a0064a7e5e6a24fba714f94fcb8a8e1e0106900c2306a44e236a8d8f3520e233ef40c82539348bd0d127dea17eed2010d141a2800ed4d1d694d3475a00964e08fa52a9e00a6bf207d28f4a009d795fa52be4a53e34c2531c7ca680153b54c981f5aae0fca29f92698124a01191d6ab138353a1cf06a0986d6f634011cbf30cf7a8315366a361480414b9a075a434012007141e47bd3a3fb9cd467ad0025145140172c5b0e315d35a382801eb5c9da92265c7ad74d6df754fad6723686c6944037038c54857239fceab0250835651c30e0f3e95258e473d0f5a7023a1a8cae4fbd3b18c13400fc0cd26c069452e2802268876a89a323b559229a6802a15f6a6151e956d93350b4641a00accb4c2bed560834c2290cae466a32b564a530ad00572b4c22ac321a615a605765a630c55823151b01401092452091877a715a6114012adcb29a90de93daaa1a6d302f2defad2fdb47ad679a8d89a057350ea0a075a8db55451c9ac7918fad56918d52466e66dbeb31e38c9aab2eb0e4fca2b2a8aab11cccb525f4cfd5ce3d2a06919ba9a6d140ae145029eab4c42a2e580ad08d36a8e2ab5aa7ef7e9579393f419a603656dabf852d8e0efcf5a64e331fbe68b4e09cfa50227dbfbc07bf152a644873d706989cb71ed4e6c87ce79a6024b9dca7b54120c5c230e8548a92e09f971432e16227d48a00639f901f7a036569f2ae52a180e5b07b1a00737039e86aa6df98fbd5b90661f7155375218841618aae41048356d7e653ea2a090646690115489829ef51d2a9c1a00b109ed5311ba13dcad56538e45598d82b027eeb0e680294830d42fa54d2a7cc462a0e86801f9e315130a9075e69ae2800ddf263de9b8a29e07c99a00231961f5a9a43f31a6daaee9803d3ad239c13cd0044c724d0a3268e49a7e06050019a693413474140098a43ed4bd7a500500368a7628a006d14b8a31400da5068a2802dd8ea1359481a36e3ba9e86ba8b2d56def23c8608f8e558d7194aac54f07152e29949d8b77d31bcd4e461c866c0fa56e5aa7970aafa0ac2d3b60b905cfd33eb5d02f4159cfb171264e48a8b527cc6225fbcc7f4a9a13852c71c55327cfbd661d138150592a9d91aaf4c0a633e69f20ee4d372a06698104bb8af5c550953157a7704e05529064d5c489158a0a72a034e2bce29eb1b019ed56402c43d69de48c53954d3886039a0084c6b4c645a577c544cf4008d8cd3334a4e69b4c42ee349b8d262908a043b79a70727bd478a5140120269e9c9eb51034f534845814509c8a281115252d256830a28a29005145140052d252d0035ce16ab1353ca7e5aaf40c2953ad369cbd69017ad532c48ed561172fd718a86d4ed04d48b2126a842ca7b0a88b1cd29e734cda73400638e69fb364609c64d20ec29c790680227cbb8a7118c510f2fc8a3397269002f1c9a427bd26496f6a4e4f5a00583249f7a6123cd3565542c7fceaa0397340c917ef8cd31c664a721e41a24e0e45022685b0e33da9233fbcf7a642df293e829d09ccabe8680121c8b96ab331fde7e155e21fe94df5a9d865bd6981049cb1fa545172c454ecb90c7daa08f892900d7186a733fca05128f9cd46c7a5218c7e5a9474a6f7a5cf340035039348d429a0043494a69280243ca8a08c05a063652c87e551e94017633fb9151edeb4b09fdde29c3ad302351f29a503229c07071481702801a4e30692e06e8f70a71a68e41534015a908a730c1c5369008386e691b93c538d2272c2802641f27350b7dea9ee08ce50102a003268000290f5a730c1a6d004d6a3f7a3eb5d5da287840f6ae62c57330aea2d94a2823a56723686c4c8481b1bb54a1770183834c619c114f4fbb9f4a92c55721b07822a5dc1bf1a601b86698772f2bdba8a00b49d053aa289c38e2a5cd0018cd34ad3a8a006114c22a6c8a6914015d863b5447af4ab4c3351b2d005665a6153560a0151b0c521906da632e2ac1538a614cd0056619a8996ad3262a365a00acc951b2d58239a615a60572b4d2b5395a615a00808a89eac30a85d69a259524aaae79ab720aa8ff007ab4462c6d14514c9168a502940a0058d726a78d7e7029b0ae4fd2a5c7ef47d280248001b8f4a9a3621493dea355c0c7a9a924c08d40eb8a60301dcad9a2dcfcc7d314c8db20fbd48a36914016a2fbb9a720dc5b3e94d418519a721f95bd7914c4325fe139a09dd0fba9cd35b395a58c1dadee28007398f1ed514687767d454ea998c71da9aabb08a0066ddd1b01daa81e1b15a69812303d08acf9571311498c48d806fad24830cc3b6688f18f7069f374c8f4a4055c7cd8a6d39bb1a46209c8a00783f28f5ab1090d1953d6aa0a9617daf401348a5466ab38c39f4abc46e5e7b8aa92ae31ed4011d237228a3b5000a3229ffc245354e052d00496c7612c7d2a297efe29c0ed5c7af34d73b9b9a004518e6826969a79a0033fdea5e7b503d08a51c50020a5ebf5a43ea28c67a50027d68a5eb46280128c52d2500262929d40526801b453f65215a0045254e41ad5b0d4b188e5e9d8d64d00e293571a763ab927440aa0f2c3354a2bb10a9001627bd67d95de1d44a723a73dab6152200150b59356354ee57324d3f45c0f5a1a27db976e956b70aab773855c5086cae4e324f5a819c83d69b24c0d40ef9ad12326c97cc39eb4ef39f1d6ab64d2827d2988b0266f5a0ccc7bd4183e86942b7a1a007139ef4718a4dade94e48d98e00a006f1eb4840ab1f6622905bb1271da8b85884014b81e94f3110697cba008b028c54bb050428e94011014f5e3b52629db9476a0448ae0514c0c3d28a041494a692a8028a4a5a00296928a005a281450043374a86a59ea1a430a55fbd494e41f35005e8784c53d4e4e3bd471b61685eb4c01db9c53d4935039fde75a9e26dbcd020c61f039a7bf4c5468e0ca7269d2901734c06c7c6e3e8298bf331c5217c263d696238ebe9480958623c6393d699160e33da82db8103e94e8e3c600e68016770a38aa61b926ac4c4106a109888b5031f17207b53ae3ef71e94c80e69ec32fcd021d1a816f213d71c516bcc8bf5a953989c01fc34cb403cc5a60397fe3e4d4a3024c66a303f7ff005a7b01907da80199c93f4a81787a997ef1fa5571d68016539973d3350bf5a926cfca698fd2a464740a4a51400add053452b1e0522d0025141a4a00957a5127414d43da95e802ddaf200a93a1e6a0b63c2d4ec3e734c051d293f87148a714e068022618e29b4f941ce6a3a008a61ce6982a59461b1509e290076a1386a5a4ed40124b26f381d2854f941f5a4443d4f4a74a0aa8a00638f4a8ea45cb25331cd005cd3c7ce0d74f6c7318ae7b4e4c1f6addb7fbb59c8de1b1658e01a7467a1f5eb514afb6239a589f7460e79a828b4386c7634e2b8e6a3439519a940c8a064518d92633c1e956338aab2e461bb835697900d002eee2933e948411ef4020d3016939a33450021a61eb4fcd3703bd0219806a322a6c5348a0084f351b7153303519e690c858546466a7615195a00aec29319a99978a66da0084ad308cd58db9a615c5302b3ad41274ab6eb55e61c5342667cbc66a9bfdeabb3d527fbd5a239d8da5a4a514c43c0e29d40fb9f8d03a8a009e31b453b77cd9a427814d5e4d005807f950edcb7a0a603c5239fdd11dcd004713f5fad5b3c30f4aa5072e455b077633da981763f9d5bdb9a41c6453213f29c7714f03e6fa9a6223ea47d7152c7c715101f2e7dea4ed91d280056f95d4f55245048fc8d201fbc63eb8a473b415f4a00255024057a555bb4db2291d0d5a6c7960fa5477a09895876e0d00520b890afad3df9888a1f1ba271dfad2f4dc0fe15232b6dcc79f4a8bdaa74fbe57d6a271b4e0f6a0068a7679cd36945005c81cb0c1a74a83cb618c9ec6aac4fb4d5c2d919a00a18e68c714f957121a60a0028a28c50007a50070286a51f768010f14dfa529e4d1d05002d19f5a43475a005e9463bd20f7a51c50018ef452668eb4001a3140a5cd002800519a41d6940a0042d487269dc6290d003083498a7e6909cd003471576daf1940527e99aa54526ae34ec6db5cfc9d7f2aa13b2c8f939fcea28e525704d2edc9eb4ad61b770217d28e3b014e094f58877a04443e94f5cd4cb101da9e231e945c762114e15288fe94a23a571d88c0a9e08fbe29163e6af245b23fad26c762ab2f534806d424f5a9e45e8a3f1a8a51c6da571d8aa4f3486a5f2e94454ee2b10629a53deacf9405218c517158a8ca077a8cf156a44aaeeb557134341a29634dcc05145c5624a4a7536b42428a28a0028a29690052d2519c5005698e5aa3a925397351d21854910e6a3a9e114013c432703d29ebc034c0714e4c88d8fa0a6057e4be6ad20f92ab8f5a9518f4140823004a4b0a7dc104281d69148c63a9ea698cdba41c500371938ef4e5fe54f2bb589ef8a41c2124503101c0a9a06c9663d00355c1c8cd491be21618ebde80239082073ce69ac711e2909c35233640e2801f6a009391914f9b896a285bfd200ed525c0fdf81408b10ffa97fa543647130cfad4cbc47c7a55480ffa41fad302e3f0df8d3882714d3d7f1a745c8e7b1a0085861c8a840ed569d70c6ab9f958d0024c0f960fa540dd2ad48374555e4185a40426957ad21a54eb4860e314d14e7eb482800a6d3a9b400a87e6a7cbd698bc30a74a7268027b73c67d2ad37383ed54626c2d5a5fbabee29808c70f527a546c39a703d8d002c9ca5572715601c8355e4eb4008dc8a84d484f1519a40140a4a0f1400f2c42e285c95e79a60f5a933f2f1400b11f9bda809fbcc536004bf02ae14c48091c9a068bf69161463d2b460e9552d0600ab4a7038ac99d08919839da7a0a90201c8a644b9a9f0315231a84038e9cd595c8e86ab30dc463afad4eadf2807ad00120c820f7a742495c67a53643c52c1d48a0094e6908ef8a514a6801a083f5f4a53d69ac33c8e0d355b3c3751400fa69eb4b49914c0298dd38a93ad34f14011914c22a5c5359680212b4c23d6a5229ac2901095cd336d4c45376d00444534af19353f9629a52802ab0aab38cd5e9179e955a65c0a684ccab81541bef1ad1ba185ace6eb5aa307b894abd692957934c925500a1f5a17eee7d284e8df4cd2afdd3ef40121fb8a7d413489449f713fddfeb4894012838151ccd8da29c0e4d473e32b8f4a0048890e7157231d7354e2e189f6ab8adf29a604f6e7e5a91c9183eb515b7238a91ce0af3d8d31091f28c3de9232cd0b8c74a211c9f7a727c9b97fbd401227cc4e7fbb9a8c7279eeb4f88e188cf14d2b8551e848a0060059368fa523e5ed883d4548846ec74cd363183229ec68029e09403d0d22fcc14e6a55192e3daa0801e47a1a431240525561eb4cb91972c3b9a9ee172a31d6a2705a3f71cd202b538734ca72f5a005ef56a0932983d6ab629d1b6c706802594670454718cb9153b7cc3e51d6a051890d00371cd0dd69ec3e6a8cf5a00423269c7814d1d683c9c50018ef475a3a518ef40051452f6a0028a4278a31de800c734bd28a28013bd2d1499cd002e71499a073d69071c5002e6928f6a3da80128a5ed4500368a5a4a002addb15738279aa94e4728c08a406a0829eb0f14c82e3cc41eb526f350cd10a21f534ef2c0ef4c0c6941348a1fb1451b5452734b834809608c3b03d855961f90a65baed4dc69cc703eb4808f8e58d5690e5b8a9dcf1d6ab9193d6980dcd2834639eb4bb47ad00213499a5da3d690a8f5a008a4e95524eb571c2d577c5522585aa664c9e828a9a08f0a1b345260406929692b7321292968a00296928a005cd349e0d2d324385a4040dd69b4a7ad252185588860540a39a9e3a009475a9a3c790fef511c718f4a7c63109f4cd302bb1c54b09c649a864e4d4d08ca11400b137ca4f72698bccc314e930a00029b0f128c8a0096463bb1eb4d3cf14b21cb93e94d43c648a004620263b9a91180b755a81ce69cc711afb8a0060e598fa518e050a38e7bd3a47558c000669010a922518f5ab72e5a55ddc715451897cd5a24b38634c4588d8631f5aaf17fc7c800724d4a8182645450f1769f5a605b24eefc69533b49a6ca3f79f8d4b1e3ca6f7a00493950455593ef5590c3cbe6ab48727a50028fba41a824e454ea38cd5790f24520213d69c9d698dd6941a4315fad2521eb4a2800a69a71a69a00075a7bf414c152372a280123abab9d8a6a945f7aaeafdc1400d73cd318fcf914aed4c2734c0b310ca9a86618cd3a17dac29f708327068029e78a4a3a35277a4021a3b53bb5368003c0e2a4404814cc66ad431e471e9415157658b48814202f3dcd39d3079edd2a7b5da990300e323de8970e3818348d1c6c4d6ad94156d07cc3159f6c76be0d6aa0c60d432912c6bc5498a45a53d2a06310e58d48bd7069a830697a366818f6f434b11c31fa52139563ed4911c39cf4c5005903349403c6683400849e951b8f9b229e4d250020e45149d1beb41e2801738a43499a0f4a0051486814b4011919a6b0cd4b49b7268021d9415e6a5228028023f2f8cd3196ac114c61cd00547154e65ad09000a49aa530da8cc69a13322f3a1acc6eb5a573931b376acd3d6b54612dc4a50706928a648f43c9f714e07005460e0d3b3c8a0099c7207a0a3bd0dd6905004f08015891db02abcdf7aad020458aa721cb1a0074433cd4ead9dc2a1846118d3e3395634017ed0fc829d2f41ebcd4101c0152bb738a602c1ebed4f279a8a16c103daa47ec69812295dc08ee28718771ebf30a6463e653db352b7ccebf4c5022aa3649f6a9642565047f1ad430e45c943eb52ca3cbd80f556c7e14010af1231355e1389985589c6d2c47ad544389c13de90c964604303c11508231524fcb9c7a5439a4040461a971524abd08a60e94012638069a454b1ed31e298d401244f8c67b5237dea64679a948e9400c6a88f5a95f87c76a89fad002638cd27bd29ce314838383400bd45028e8696800c52529e2931cd0003a52f6a28a002933ce283c60d079a00338341ebc51da81c8a0043eb46294502800eb451d0d1400521a5ef4500368a5a43400945145004b6f2f96e0f6ad546575041158b56ece60a76b1e2a5a2a2cd01b7d69d95c75a84c91ff00785279d1e7ad458bb93e47ad3a31bdc28aadf684ed9fcaae5930fbe7bf4a43b96cf002d4723724f61c50f28009cf355a6988da1467d6900b2383d8d424d05d8ff0d009c76a6000fb52fe14a09f4a5dded400ce69a73521269a726802261503039ab2c334d11e4f2698858c10b454aa9c51480a1494a692ba0c42928a280168a28a40151ca7e5a7e6a294d004549451486396a507a5443814e140163ab54ca311e2a08ce71565be5419a60533c9a9a01c54406e6c53c3145623e940085b7498ed9a77496a24ea0d4ca32093da80076c213ea69a395a46392076a55f9509f5a008dc52bb64803a014992cd487ef52017a119a6cac0ad2336291b95a006c5f7eadaff00abfa5558bef55c8c8db8f5a6048702118f4a810ed9d0fbd592bfb963e82aa1e769a622ecc479847bd4c883cbfad5690e661f41565495207bd00560a4861ef51b0c363d2ac28c4b22d44c392680114e2326ab4839cd5b8c8287355263f31a4040c29452919a4e948625385277a514001a61a71a6b75a00053b3c53453d464fe140027deab4ad818aa7d1aad21ca500239e94da730a4c60d001eb522b6e1cd318f229334011bae1a929f2722a3ef400e14def4e1d69a460d003c267157203daab435622e1a91ad3dcb8abf286079a5760791c1ee285e9c531863341bc916ed230f907a11f955a89d94147e71dea95992ce101c16e2b46588c687e6cba0fcc526668b1110501a767755681f7a2e0d5a51ea2b3188c08c50c38a90af4a695cb03400d2309420fde1fa5398718f7a48c62439f4a0648bf2f4e94fcf14940e0e0d201690d2d2668018fd3e948791d69c790698bd70680014b4b81486800c51f4a31c52e2801052e28c5140098e69dd3a521a3da80034c6152e38a6350056986481f9d676a0db63c0ef5a4c3824fd6b22f5f7c9c741c0aa42667de10b6e17d6b33bd5dbd6c102a95688e796e21a28a298851d69cdf7e9abd69edccbf8d00499c934e519229b8f98e3d69e9ebe9400e9385e2ab1eb53ca7083dea01cb0a00947cb0fd6841fbb34931c003d29c9d0500598c1186f6ab2caa6503b60d562dfb93ec2a4e40534c023f9a50bdcd3dcf031f4a8c3ed9d587639a7b630df9d00391883f4ab08723dc55507726476eb52c4e55b8e869886dc8d93a38eb9a4b825955bbd2dde1bf4a597e68f03b734011cc72aa7d4551230ea6af37cd6e0ff007081f9d522724fb5219238dc011daabb8da6aea806038f4aa9374cd0021f9908fc6a21e9532e06314c9176b629004470d534c9801bd6abaf06ae67cd836f75a00aa386cd4e3e602a265c0a7427268011bef9a8df9a9a5187cd44dd68018fc1e283cf34672c680306800a5145068003c8a28140e41a000f0334846573403918a07a5002e72b8a4140e283d6800a075a28a000d1451400514629475a004ef4b8e697bd267068000bcd1b68cd19a004d9c5214a76e149ba801a57140241a526928034ad11658fa0c8eb5645b0f41f9565d9dc18250ddbbd6b8bb0c010062a1a2d09f6718ffeb5288b03826837431d290dd1a9287f97f5a3ca07b5466e4d34ce681936c03d28200ee2ab1958d34bb1a2c2b964b01de98587ad5725bd69bcfad3b05c9cc8293cc18a8334e520b0a2c2b937514e5527069a0f153443777a9630cf6a29d8e68a4332cd21a292ba0c028a28a005a4a5a4a000d412f5a9aa090e4d0319452d25201c29d4d51f3549de80248855994fc839ce6abc1dfd6a67e5453023500034c9784c549c33003d29973c1c5004687a5591c447d4d5443d2ad6410076a4042dcbd2c876a8149270d8a8d9b26801f08c9cd349e734e8b015b3e95139a00693934f1cad4752c66801a060d5b8813103e86abb2f06a7b76f94034d01724ff54c7d2a81e31ec6aeca0f959ec78aaac029607b734c44a0fcea4fa0ab4fd41e9cd579863cb23b815667e40c7a0a00894e6e481de98fc161e94a0817071eb9a4947cede86801911ea2abcc30c6ac211b88ef50cfd6901028e69075a507142f5a431b4507ad1400535fad3c7514d7eb400829ca7e614c14b400a7ef55888fcb8aac7ad4d11e9401330e334c63834e634c619a0018e56853ba8038a6af0f400e71815166a6939150e39a0051430e6957de87a0054e0d5885be7e6a08c82b83d6a58cfcc291a41ea68c2c08c77a0fcc48c53606a7b6472283a9ec322629203d306b6add3cd5f34c84c807009ea2b0c1f9eb4ad06e4cab61bb7d68322484f9737fb2c73f4ad45c15aa4f1462353c8de703d9aa4b69b2acadc329c1152d0161b208029714a9cf5a715e78a802371c8a231f39a7376a231cb5003a82334b8a5c5218da08a3a1a2801a4546786cd4a722a37a0033475a414ee2800a51494b400500134b45003719e94e0314e0b4b8a004c54527240a989e2a163c163d298156edf6c781d4f02b16e8912ecee3ad6b93bd9a56fb89c8ae7ee26e6490f563c5344c9d8a77443ca70781deaa9a9646a8ab539d851451400e14e3cb669a29d8f9f03d68024a78fb87f2a61a95572ab8ea4d0032e06d655f6a8e25cbfd29d707370d8edc5221db193dcf1400d739634f43c7d2a2a917ee350059539b57f5238a990e61407a7ad555722223b54b065a327b0a602f47153e471ef5011820fbd3d9b853ef400e8beeba77152c6df20cf6e2a02db6761d88a917e66da3d33400b311d28470700f43c547264a734c27f43400f3260327a8c54054658fa8ab0ca3208ee298cb84e7d71400d81be523ae6a2987ca0d4917de2074cd2cf191b87a734015d0e179144bc81ed420c834a3d0d20211c1ab5698f39149e1b83559860d48878c8ea0e680259a228594f543835143c31ab53c9bd839c7ef179fa8aac06de680249d308ac39cd576ab45736c4ff74d5561da8023c7714eed48320d2f6a0009a4a286382280141c9c522f048a43c353987434009d0d07ad2d250014b494bd0d00145145001de8ce28cd20e7ad0029349d7a503af340e0d00039a3ad1de83ed4009d68a5a4a004a2969280128a28a00055a825e3693556954e0d21a343703de80e05408c185387d29587725f3051e67b547f8519348648643e946f351e4d2734012331c54649f5a08349b698833534239cd438a9e3c85a4c64a33daac4436ae4d411649e6a7271c5432d0f4e5a8a58c6173eb4548cc8a4a292ba4e70a28a280145140a696028014d57232d52193e6c76a61e1e90c40bf360d28e1e909c3e6827e6cd002a9f9e9ea33518fbd5345dc5003a2386c54cc403c74c5575fbc6a566dd8f614c014e0b1f4a86662d827d29fc95cf6a63ae14500363eb563d2abaf5ab084e01a4043272e4d3714ec139cf5cd23f5005002af4350b75a9c0fdd1355fbd002e2945068140139198030fc6a481791f4a8e07c2ec3deac463128c74c5311248e426ced9a8a6501b3fde5fd69f303e6027da96700b27a63a5301b23130c67d38ab6eb98c7fba2aab8c4207a1cd5f8d3cc8948f4e6988a0dc5d281dc54ccbf3907f0a65d0d9321f6c548e434991e8281902615c92326a0bafbfe95617fd6d57b9c97a960418a070697bd25218d348694d2500148d4b48680105140a28016a48ea3a922e4d004c0648a4c734e5a5ef400ce8d4dfe2a56e0d368025c656a1239a950e45358500340cd2374a70eb4e651814010a9c354e0f422abb75a9626278a068bb04981cd5d55df1e4554b3b692e25548c64935d3c1696ba741e64e43391c67fa523a632d0e72e217898165201e6acd94d86e7a1eb56b52bd17e3ca8e23f2f438e6b26390a375e94c46ded50de639c8e8c3f91a7b3072648c7ddfbdf4aa30cbe6704e73d47b569abc5044a0019e847f7852605984e40a96aa27eea411824a9e54fa8ab28d9159b42090743444300e6890f14b18f9690c71146294f147bd00348e2929f4c3c1a431add299b726a5229a46280231d28a5239a314000e69dd29a053c0a002940a314a0530168c52d231c0cd2018fcf155e5cb0da3a54e4161f5eb54ae6e02bb28e8bc53114753b8f2e1f257a1ebef58374dfa55bbc98cb3163d0702b3ae1b26ae28ca6c849c9a4a28ab330a5a4a7628001d454b10cbe6a3519a993806800ef53427e6fa0cd438a7a36d573fece2802be77393eb4f7e102fa5317ef52336589a0029e0fc9f534ca51d2802453f211535b484232f6cd40bd0d2c4c0311eb40168b64530b12b4d3d281d280253c856fc2a589b6cc9ef9155d5b8c76a7024107d29813bb01b95aa0638e9534e32aaffde155cfdd340126fcc2a7d38a767311cf5ce6a18be6464f4e69e837639a004523cc23a54d747e58dfd460fe15010430fa54921cc007f749fd6802b0f95c83de9b4bcfad1c734806c833cd2c079c1efc50794fa5353ad004b82531dc1a9197f73bbd6901c3f3deac46a0da953d5734c44508df0b0cf6aaf20e73ed53db1f9641dc7350bf5340108a1a838c5373486293c504700d20e94abc8c5002e32051da81c7141e280128ef4b824d2f7a004039a294d2134005203cd1839a5a004c60d14b4940051d681d68e9400940a5a4a005a4f6a28a0028a53494009494b4500251451401242fb5bdaac8208aa42ad5b386e0f5a4c68928e6a5da28db5232300d2ec3526dc76a692474140c6eca08a63bb7614c2f21ed4c0955726ac228c75aa4be6eee3152f9339fe3c52605f50a17ad20049aad04522b65df3ed56d640bd05432d0e91c46993c0a2a0ba2265009e3da8a2c067e6928a426b731168cd337535d89a403cc98e951b9cf348391476a0018f43431cd2678c5250019a3bd2528a0070eb52c470f517f153e3fbf400f886588a57f941a488e1cd12739a00546fdd6298e49a3f82933902801476a941e2a31d29e9f749a0073fca09ee6ab03f366a491f70a605e33401213f262ab9eb522f7a8cf5a005cd2a9e69b4a3ad003fa1157a2f9987ae2a81ed572d5be714d012de7c807a669d20dc6334dbd209c7a1a5604c48de9c5310d76f9196af5ab11003ed54a68f6332fa0ab76a7759a8ee0e28110ddf273dc53a4500e4775149743721349237eed7fdc14011295dfef515c0f9a947df27de9d202464d032b15c914c2307152afde02a36fbe6a4630d34d388a4c5001487a52e290f4a006d1451400b5241cb62a3a922fbd40165072477a407e6a7c63bd358739a60318734d6152b01814d23e5a008d49069cd498c539006eb48060eb4f27238a6746a942e509140159fad2a36d3438a41d280346cefded81d9d4d68594577a986656ddb7aee35851d68596a33dbc8be41da40edde8348c8d52b75a69ddb02b1e338c8ac99f3bcb11826ba4b0d6e0960315e263d78ce4565eb32dbca889691e110e7763ad06a55b6728430adcb47428a4f38e47f515cec0dd8d6a69f200c109c64f1f5a455ae8d12eb312b1e72bf321c7e62a785c3267b8eb51997620444396fbb8ec6971e5c9e681857fbc3d0d4b2499c8dbc53e3c802a1761818e8c6a74e95203873411c50296900cce3ad0dd29c71484500341c8a6b52e70d8f5a0f3486467ef518a56a0d301075a78a653d4f1400a39a70e94d14138a042b1c0a613b881da9704d42d21cb052076268012e6508a55396fe558b79380a514f4ea7d6acdd4ff00332a740319f5ac7bc95570b9e7a9a69037645599f9aa6ed93524cfb8d435a239db0a28a5a62014b451400f8fad4a9d0d4238a993a0a000f5a46388cd07ad35cfc98a0060e149ef4ca73700536801c29fd05463ad4871814000e9483ef52668ef40138e452823069b11cf1474a0050706a6c800557cf5a955b728fa5004c5b74207f74d42c78a7a1272bea335131cd000a7120f714f53b5f1511e80fa54a5b0e09a0073fad4a803c4ff004cd4470734e85b68c762314c0ac4056c5211b4fad3a6003f4a69c15f7a40087e639e86900c1a4e845389e68024032cb56a000dcba13c15c8aaa9d7e82ad44b9749475e87e94c4428be5cee3b1e2a19786356ee86c7561552ebae7d6802bb1e6929334a290c55e0d3ba1a4c719a5ce45002b7a8a4c67140e4734e3c50021e2909a0d21e94006697009a00a534009d29296928013bd14a7a6681c8a0028ea2814500140a31450014514bda80128c714bda8cd002628dbf2e6973c519e2801bb28298a7e78a334011e0d2a12ad9a7504714017a370ea08a901359f04be5b7b55e47de322a1948764d35813de9f8a8dc9a45588da9314a68140ec3e25ef53d469c0a5046690ec3bf1a4269c55477a46da178eb480616a29b9a2988a64d2519a4ad4c829a4669d4500317838a5ef8a1877a4079a0069eb494f71cd32800a70a6d385002f7a55fbd41fbdc5277a00910e5a9cd4c8ce1a9cc7e63400ccfc942f349fc26843cd00487ee814bbb11900d0dd78a8c9e2801a4d4ca3f725aa1ed52b902003d680235a6b0e695691a80129693345004841c0ab566a0c83d85564e702ac5ae45c1c76a603eedbe65f7352a31fb337b106aa5dbe641ec6a6b6937074f51408964626519fe25a9ec5bf7641fef540ec49849ec314eb56dbb8770d4c459bc03cb381c62abb8fdda1ff66adca37403d4e6aa13c05f6a00ac787a9997f760fad42e0a9f7a9d8feed71d3140cabb70d513fdf3563187a8a4539cd21911a69a79a69a40251452e38a006628a0d1400b5245c1cd463a53e2eb401722f989c7a530fdec1a20ee334f600914c04238a61e98a9c8c266a13cb5020db94e69231834e504834de940c8dc624352a1e314c9befe477a747c814808a55c5478a9e4a8b140088706a68e5789c3a1c11501e0d48872281a356c2192e88603033cb7a574cfa759d85979ad99370c16c66b8eb5bf92d93621c735bfa56ba96d0f95321955b927bd06aa57316621273b410b9e3356217c30356b5bbcb6bd08f04651c70dc63359913f6a46916749038950483af43ec7b1a952533b949170ac36b7b37ad6669d3ed7c12369e0f35a4ecca8c02824f53e9ef48248452576c527de52055d4e9f4aa53ab15466e244c6ec771eb5651b3861c8a96493e29391406a5a9189918a4cd2e39a43c8a006b74cfa521e94a7a53474a0635ba5252b5373400a29c0814c068e73400fcf34a3ad34baa8c9205412ccce36af00f7ee680259a5fe14e4d52b895618f0586e3cfd2967b85b78fafce7a0ef5877533be724927bd0909e82de5e0ced8ce48acb9092c59ce49ab018460e4658f73daaa4af935a24632772363934da296a881294514b400503ad14a05002819352f4a64639a7500283cf34c73938a5a8dcf268011ce4d25149400e5eb4e279a60a5a005a2928a0096138706a49387c5408706ac4c73b5b1da8023ef5246718f6a8bb8a703834012ab6d9037a1a1c0f308edda984e6958e403ed400def8a7b9040a8cf506941cfd280268b054e681fd6a38cf38a7a9c50017030471d6a0ebc558b8276ae3906abe706800c6452e3e507d292954f18f5a007af0b9ab76fca62ab36046b5242d814c0b172b9da7b551ba20a0f6e2ae3b6e00d53bc3c1c74eb40152940cd252d201c3d295460f3483939a78e94001e948791467b5274a002814014bda800a6934bd45345002f5a07340e281c5002838a4e94a451de801314b8a53499a005a4a09a43d280034668ea293d8d002e683d33494500145149400b4945140064d19a29280173562d65dad8278355a80706931a364608cd46dd6a3b59c32853d6a623dab366ab5212291539a9761f4a7043d6801a0518a7114847bd218d34da7118a4a042514b8a2988a14b4515a99052d02971400c61c547dea6238a89860d0039b95069869ff00c14c340094e14da70a005cf3477a0d1400a3834e14da51400a4714c419614f142fca73400f97802a2a73364533bd0014e91b31a81d85369cf8c2e3d2801a94374a414a791400ca514525004f10e454b01cc848eb5145eb525a63ed073400dba1861ef45b36261efc52dd90641ed51a1c3823ad30343e62a17b039a7c4bf34bedc8a6c44188e7ad01f6c800eacb8a622d96ca05155f1cafad4b11c8ce79aaf22959b140114c40907bd4f8cc6a07a555b9f95949e95610f4f4c50046410f8a649d39a9c00589f4e6a19ba9a40566a6d38f34847148634f5a55e32297146393400c75c1a6d3d8e4629b8a0001a721c35329c3a8a00b50361aa6db9e86ab038208e956d3ee645310e03e423ad576c022ada8f97ea2abbaf5f5a6039471c77a84f5c54e9ca6476a848c3f3de9011c8bd29632454b3a151eb50a75140c74eb8e4f7a8338ab93c64c20d5403ad201a7934aa71487ad140129191914e8a4208cf5a6c5205f958641a59170c0af4a0699bb65a54975089646db19e78e49154af2d459de3461c32f63ea292df55b88e2f251c85ed50caad20ddc9341a2916a06da7ad6cdacfba31b8fcc9d3dc573b1484119ad1b6988c1148dd35246d2192697242908307dc7ad2ae619cc4e783cae7b8a86d1d846c633f7b91f4f4ab26377b701c0675e548fe54882553da9c09155a2932a0fa5580735003a93a519a5ed4806e699dcd3e98c08228011ba5478f7a93a8e6a3e82818d248e869ace40e49a46936f4193481198e5cfe14808cfcdcb1e3d2992cdb173d289e51f7632303a9aa93b9f2f730c7a0f5a60569a52ce58e7fad54b9976803bd3e793664e467f955191f7649ab48ce522391f9e4d4279a79e69a455190dc52814b8a71c04c77a62194514a2800a728a4a7c58279a007a2e05211c5498a187cb40101e951b54cf50b50036969296801451451400514525002af5ab1bb7263d2ab8a910d0029a5ec291a807e5a005cd283483a519e68014f205203cd2e78c536801ea706a453cd439a963e4d0049364c631559b39a9e4c94527dc5426801b4a3a8a28a00949063fa1a92d705803eb5003943f5a92ddb6c80fad302e103611dea9dc2663aba305b9a85c03030cf43401974a066948c1a05201ebc75a09c1a4278e280723068015b1d45340268ebc0a7018a00293a9c52938a46eb914009ca9a3bd0791401914001a5c52e283400521341e948791400a4d0464520e78a3a1c50003de8e9411463340074341f5a414bd0d00275a294f1494005252d1400945140a0028a5a4a004a28a2801c8e51811dab4629fcc5193cd65d3e372a6a5ab949d8d50d4f1d2ab432ab54e1b350d1a5c534da942e69fb001923a5481588cd215c52bbe0f0298cc4d30168a8f9a2988ab453734b9ad4c85a5a4cd28e9400532414fcd237228023078a69a7630690d00369c29b4e1400a68a296800a075a28a0070eb52301b78a8d7ad3b34011d2539862986801695ba0a414a7eed0036945252d0034d253c8e69b8a009a2e83dcd4b02e2e9867806a1030ab53c23f7a493c9a0086e7fd71a62f0c0d3a73f3e6a3dd401a16ee1863b54ceb8287f0aa56cd86abaec4c59f434c411b00f8f5a96e86248dbb32d56e9229ab13b6e8233dd78a6053bd60401e952467720c7a54571f3649a743cc781401322e18fa114c99339ab2171106f7a819b2d8f5a00a4460e2823e514e71cd21fbb486263914acbde9c06e229594f7a40576a4ed4ae306940ca6680194b4114a8b938a009d70c82a785870a6abc5d315328dac334c0b8abf28c734c9e324f02a6b7198c9f4e695f04035422890637c7ad2372bd39a9675f981f4a6f7fad20149f3611eaa2ab01835611700d44461b9a405a5264b723ae05671e0d5eb77da42fe155655fde49c5032171f3500646683ce2856c1f6a4000548a72314dc6391d29475a0054c0604f4adab6b882d195e37120239e3a563b60e0e3b734e8bef63b5034c9673bae1d907ca4922a7b798a8c1a49022440a9ce7afb54092e5b1d0d06919599bba74e412a392795fad6aa1924906c6183f30f63e95ce5ab7ce0e4a9f5ada89d9957ca7c3b75cff007a91abee58953ca973fc2e7a7a1a7a1dbc1e9481266b7fde056f33918fe1351c7371861865e08a96892cd19a8f7e3e94a181a918b9a46ce28c83e94d638a402f514df5a14d2120024f005031840ce4f26a0b8721707bf6a1e72c488b9f7aaf238894963b9bde818980aa59f85159d773b3e081b54741524b334ad973f28e82a9cf20ce73c5344b2bc84b126a03973c74a9f6b487d054be52c50ee35664d145976d369e7323e053fcbda40a640d8a22dcd4727dec55c6223b7e3ab5513c9a620c514a052e28012a68538cd458ab087098a00520e298c7a0a9b042542eb8614011b773509a96538150d0014b494b4005145250028a28a280169c9d69b4abd6801e6901c0a5eb486801ca7a8a434dcd293c5002e69734da2801d9a9233c835153e334013b91e5e3deab91ef5231ca9cd45400bda83c52ff0008a1c7cb400829c8795fad313bd2a7534017e438d847422a227923d6866ca0c503047bd3028b8c39a406a4b8187a8a900b41f6a295466801ca3028268e94d279a005ce460d276c5203834e00e734008053b1c52803149d6800cf149d450a7b1a4fba680007b1a3a1a08ef4751400118e697ef0f7a14f6349d0d000a7b1a3a1a08ef475a000d1d68071d68e86800a4e94a79a3b500211e94519c5038a0029294d2500145145002514b4940051451400f8df6356adbba48831d6b1ea486668d8106a5ab8d3b1b898cd2cb2054c7ad43693acc9c75e945c72d8f4acec6840e413914da71514a101a60474548100ed45006652834e2b51918ad4c87834ecf150e6a453400ea5ed494a2802361cd36a4714c1400d340a56a41400eed4b49da96800a43d696971400a3a52e690507ad0007d2a323152b0e01a5da1d3afcc2802214a7a50060d2d00328a5c518a00073c521eb4b487ad0029278a9e324b923d2abd4f077fa500452f2d4ca924e7151d004f6e7e6abff7a223dab361387ad08186d2bef9a60464e4fd2ad83bad5971d0e6a9c9f2c9b6ac4326494ecc2988ad21dc062a7b71fba27b546109e314e88908467bd005ceb6adf9d5460038357add418483d3154e45f96802acbf78d30f4a97193cd4657ad201ebea3b0a7eec839a8d783f515200378cf4340cad252274a9264c311e86a38fef52017666907caff4a98771e86a375c3500397ef134f27e6151a548c3a530342d1f284539ba1155ed24dbc55d700818aa115580c546cbf2fb8a99d0e0fb546a73c1fa5003508c546e39a711b703d4e29fb781914808941de0e78a49947986a407048a4b8eaa7d450052718a61a964e49a662a462a3763d28e869bd29c39a0091483c51c839a6af06a6e08fad3024470d160f51513281c8a14056c1ef52a81b7a71eb40c75bcd8c026b6f4fba5dd86fba460ff008d738c30722ae59dc10473d291ac27d19d3c219df6190ecddc91d8f6a96e63db22c83073c3e3d7d6a9dbceb2052df293f2b11fceae242446fe648581e1bfc69328543918f4a318e45411332b14272578cfad5907daa18c060f2290e31cd35f8f981c5479dfedf5a9011e50ac554126a374debfbd3f2fa76a5919633ee6abcb23375ce07a503096654188c003d6b3a6937b67b54f30253749f2af65f5aa12cc4fc910fc680239e7541b4726a2860799f2ddea586d0cb26e6e6b452008981f78d508ab1c001f65ea6a8dfcbbe4dabf955fd4a710208232371e5b159f6b1192704f39e6990c9edad36c7961ce33513afcc4e38ad1906711af155678c0ce38038a684d14277c9c76a82a49797a662a8cc2945253d0039cd02100c902ad46831cd476f1ef24fa55909b52980c93ee81daab93926ac4c7080d55ce173401148726a3a7375a6d20168a0529a004a4a28a005a28a2801474a514d14e1400ea4a5272052678a00434b9e29281400b9a29296801d4aa7069a3a5140133106999c5213487ad00381e29cdf72a306a463fbb1ef400c5e285fbd480d0a70d9a009d4e52a488e587a5431fdda922e940115e7dfcd57ab13f2b9f7aaf400548a38a620e7269e4e2801ac69b413cd2a8cf5a00555cf34fe9c52741484f71400679c1a43c3529195dc3b5006e18ef4008477147514aa7b1a4e86800078c51d0d047714bd450007d451f7a901ed47434000341e0d07da8eb4001e681ef49d294f4c8a003a521a5ea292800eb4a3d2928ed4005252d14009452d2500145145001494b49400514514012433344e0a9abc972251ef59b4e4728720d4b571a763481a7024556825ddd4d4f8a9b17714b514def452195319a632e69e0f1475ad4c8ae460d283cd48eb511e0d004a0e69d51235494003722983ad3f04f4a69e0d00358532a43c8a65003874a5a414ea004ed4b4bda9280014a690529e9400efe0a8f241c8a703c536801d80c33de90d00f3c53f6ee3ef4011d14e208383498a006d2114e2306928012a58aa2a9a33c500324a8cd4ac3279ef51d003a2e1c55c84e24c7a8aa49c30ab89c303400fb8ff5a0fad3ed9bf7ca2a399b38a743f2be6988b0a83ccc7be2a0914293b7a6ea9837ef1c8ecd51dc1c2671de98166d9ff72c3b8a88b065607a834eb520a803b839a69522571da80202a4483d08a474c1c54eeb84535149f7a802311e64c67b669d3aec2083e940e24e7d2a5b853b00f6cd2020946573eb55d065b156d9488f9efcd56c7cd401201861ee29245f9777a53ce36e7d287194e281912720d3bb53569f81b2802485f69ad3470e808eb5909d2af5ab653e94d012cd9fe1a89141722a47cae73d2a34cefc834c43187241ec69e57f740fa1a92ea11f248bc6e14c53f2e3da901037dfa49b9404f6a7483072287195cfa8a00a4f4ccf352b0e0542473523148cd038a5a28014633cd5840193e5155854b13ec6f6a0079041a910023ad2be1c714d41c1f51d6980a530698c0c6c197f2ab2855979a6e3b1e47afa5032d58dee08573f2d7451229f955f008ea3a11d8d71ee8d1b67b568e99a8b44c01c1006083dc5268d232ee6edd218c07c72bc3e3b8f5a7c32075e29b04ab247e6b302ac36b03e955b0d14c517820fe950cb2e9c0eb5149cf232295727ef7269491dfad40cac633d587d2a392558949c671566691550e7a5654a1e5eb90940cab34925d4a700d4b1da8242a8c9ee6a68a304e231f8d5b40902e38cfad0046225822c9e3fad51b9ba21488ce09efdea4bc95892ccc71d855444c82ed4c0a7e59c967e49abd671941bf1d7a530c7bdd57d6b4921e0228e14734c9b116cf2d4b9e58d66dec855481deb52e5b8c2f6ac4bc7dd260741d29a265b1548a00a5239a5ab311a1734ed9c53d4645285cb014013dbc4557353903007ad2c7858f9a7ed057354228dde3705155e4e16a79c6643559876a4322a4a795205369000a0d382f19a61eb4009452e28a004a5a4a280169452528a005a28a2800a4a5a0d0014b4828a0070eb453696801dda8a414eed400da796cc6053297b500039a075a1690d004c846ef634a5b0062a253de9d9c9a0025e63fc6a0ef565f98dbf0355979340120000a639a793c544793400a3ad3fa0a68e2826801739a4078c5274a5f7a00553b4f34746e28ea281cd002b0cf2293ef0a01c7141054d000be8683f29e283cf3475140011c6681cd00e0d078a0001c1a08ef4751403c62800ea28cf6a4e86968010f14bd68a4e9400b49d283cd028003451d28a0028a3ad140094514500145145002514b4940051451400aac54e455b8ae7230d54e80714ac34cd10f9e945548e62a71452b1571c2978cd20a2a88022a375c0cd4b4d619a0080715229e29ac39e280706801ff4a4618a5cd073d4d00369a69fd474a6b0a00169e2a31d6a41400a7eed36973482800a33451400535a9c29185002669eadeb51d28a0094e0d2114d069ea6801a4530f5a9f19e0542e08340094f8e9829cbc50039f919a8cf06a64c312a7b8fd698ebf2023e868018bf7855a1df155055c8fb7b8a0057219453e33dfbd47fc34f4c002988b116199f3ed4dba1f22f18eb4b6c4191c1f4a75d0ca83f5a6032c1be4ebd2a60479849ee2a959b1c1e7bd5acfcc33c1a006ccc4c5f8d122f23e8295a32c3e869fb72c3d3140155c65ff0ab2c437939e857155dff00d67b548cc3c98bd41a0069071b4f4191559c60e6adcff2b82bd0f3503ae41a40229cae0d49174c53221806a58bef91eb40c84c7f33629a3938ab2c9827d2abedc373400e5e054b03ed7c5300e69a3870680341c96ebdc55604e783dea52414e3b542171263d698171cee8541fe1aaea70e3f2a9ba478a81971267bd02165076f1da987fd503f854f20cae477155c31f2d97d0e6802bbe315111915213f311eb4dc76a9191d380a4229f191d0d002014a01a43d69ea4f6a00546e393572d02b382e386e0d51c739a9e0720fb5302dcd08b79361c107a1148232141e80d5ab286deea395266d9201b90938047a5452958cf95bb7053c3531903a6e0548aaac1a37f7ab858e73d689a3de99007f85003ec6f9d1b697c2370c0f4ad924342248db73463079ce4572ac190d4b05e4b0126362011823daa1a294ac7571ce180e39a79208f5acad36f92e0047203ff3ad2e53dc566cd53b88f1eee5ba0e82a0f2f25b774ab01f7738fc0d31c6e604f41d690c8b6851f20c0a6b608dc474e953e01fa7a545381c773d80a06519222efb9fa7a5208fcc703a22f5ab4ca42e1bef1a6baec8f62f7eb400cb38833b4c470385ab454aa903a9eb525b44044334d9085534c464ddbed079aca6f99b26ae5f3ee98a8e9558ad5a3291111934857daa611e066938c551037a0a7c2b97cd318e70054b0e40c8f5a622d32e3681f8d3fa2f1516ec2ee34ece631ea6802aca3926a38e35665ddc73cd5920639a604c820f5a4558af32aaa71556ad5d285e01aa8d40852c48c5228dc71494e51cd02259a0f28e01c81dea0a99dcedc1e950d001452d2500145145003a8a414b400aa7079a08a4a280014504525002d14525003d6969aa79a7500252f514d34e4ef4002f14869cb8a4c64d00038a28c519c50039cfc98f6a8d29c46569107140039e2a3a73d368017349451400b474a4a5eb400a38341e0f1494a0f6a0053c8cd00e462901c71474340074e28e94e2370c8a41cf14001e46681e9474341a0007068340e6807079a000734743411dc503914001f5a41cd2838a08f4a004e9452f5a4e940051d2971476a004a28a2800a4a5a280128a28a0028a28a0028a28a004a28a2800a28a2802714e3cd3681400e1d693ad00d2f6a008c8a615c73531e94c6538a006034fc9351f434f46a00706e718a461c519c529e9401177a78a611cd39680168a5a280129283403cd002d2e33c51499e6801a460d28a711b86475a681400b45145003d0e0d0e339a683834f382280211c1a78a691cd2838a00524a9a5196047e34d3467073400d1d6ad2b6d55355bbd4e1b3181e94012aaee069186d61442d86c1ef52ca0000d3016d47ef1c9fee9ab630f6acc7b0aad6c3e727b15c54c5b31bc6a6988a165ce6aeecc48a739aa1683f7a16b43ef43bb1c8a0079fbc78e2861f28a7c87a301c1514632aa474c531145d7e619ee69b32ed850e7bd599133b4fbd43391e505a43109df1a9148a37673490380854f5cd3946d908f434009b718c77a50a51867b53df38e3eb4e23732e3b8c5031ea372922a1963caeec74a9206dad8352a2871227a8a04538c12bd298c39e69f0b6c62a7b5128cb64521922b662a6924aa914913755a507191da981643e714483baf6a8a3ebfa53c7de20d02151f80bd714c703320ef8a07121a25c672075140145bd69e30cbee2a393da9b1b95606a4639c7a533bd4e30ddaa265c1a0001a72b638a6548064034012491e1432fdd34c538a957263db9f97ad42ca41a605c8df0b9fd6a74db20c1c55188e571561010323a50344bb76b6d6e01efe949246f100e41d87a376356615492d8b9cb480e36e38c7ad1b99a1d872133f73b0a6558a12619781cd543f29f4abd246636ff66abcb1871c5224890b230743823d2b5ec35905952e4fd1ab213319208c8a7ac61b9152d5ca4ec7560abe19482a79c8a1b9191c8f4ae7ad6e66b5fbbf347dd0d6e5adec774a047c363907b566d58d53b9375f6f6a0263934f0063de93193b73f5a4510b2e79c7d2991c3bdf3dbb54d303c28efc0a95171d3a018a042a8c2d50bc7eb8e9d2ae4adfc23f1accbd7e768f4fca9a119137cd31a00dcfed4ed9b98fad588e1c1e7b0cd59162274da86aac830302b45a30d8aa522e5b14d12d112ad4e876a80699b4814a4f229923d9f2c16a653960bdcd40b82c3d6ad5bc5f396ef8a1b1a43767cf8a8e7c24bcd5c541bdbd8551be1d0d4dcbb14266cb5406a4939a8cd519882a685371151a8e6b42de0fdd827bd034ae57993daabb0c56a4f6cd8ce0fe559d2ae1b046281b5622a2834504051451400b4b494a3a5001494b48680154d04525389c8a006d145140053fb5329d400629c9d4d36957ad001499a0d250029a3341a4a00776342f4a0743482801afd69b4add692800a5a4a5a0028a28a0029692968017ad039a07068f7a000706948c72293ad283d8d002939029b41e0d29e79a004e94a79a07346314000a3a52e3238a407d6800c668149d0d2f5140063bd28e78a4068c62800e869297ad2500028a28a00292968a004a29692800a28a2800a28a2800a4a5a280128a5a28026a2928a0051cd19e692973400bde918e68a07a9a008981a10e0d3c9cd47d0d00484e68cd19045250021a45e29c45368024a2914f1450021a6d38d277a0051d28a5038a0d003734e183d69b4a280020d2e29ca78c1a0ae2801b4aa79e690d20a0073e38a4a31c502801314a4714a0734bb734011d3c36169a78a5fe1a009e23f74f1562e48f2548eb8a82dd77a123f87ad4b70316ea7d4531125a0cb2fb8fe952a21323003aa9c54368773a63b5588e4225427dc7e94c0cc858ace0fbd68861e4baff00b559a7898d5e88ee8db1e99a00b88a4c6a4f4c629ee87ca18ec6a285cf91c1e86a72dfb9f5e6988a8dca0cf6355a619538ed569c022abca7923da8632a2b6d7a9ddc0941ecc2ab38f9a9e1b2a0fa548cbbb77c61bdea3f308e3d0e69f0b8318a8e45cc836f5e98a621ee70e48fad4e8700483f1a888dd6e18f553b69f6cc082a68020b94293e71d6a227357ee23ca67daa971ba818d5251c352eec3d2b8e315131a404caf86ab120070c0f519aa41ba55946ca0f6e29808d9dc3d295b3b4fb5365c9e476a4524d005593ef9a628c54f2ae1b350f7a404a8695d770a628cd4c8772ed3d690158f1d69ead8a595715176a00b31361f07a1a92450c0e3aad5646e055a43e628f5f5a605756c362acc739523d47eb55a452af4a1f70f7a00d4d3ef1ed2e1654e4775ec47a56ef9f6931fb5411872a3e7461c62b9447655ce33ea2a586e5d58ec6c2b7519a0a4cd7d50d8cc14d8a1527ef0cf158d34254e57a7715a70d949222b861cd32780c321575dbf5a46bca998f2659723ad36362bc8ebe95764b462494fcaaa4913c673da821c5a278a4dc00239ab30ab2b868ced7fe759aac54e6afdbceae02bf1ef52ca8b3460d49d5f65cc78623861d0d68c6eac32181ac760dc098065ecd53a0689739257f954165f8c6f959cf6e054c4e0555b67c46335603063f4a4035f08bcf5359174fb8b1fc056acbc82cdd00aa11dbf98db88e3ad3114a084a1cb8f7ab71a931127bd4fe416cf15218bcb871e94ee067943b0e07354cc4564cb0ad58622ca5bb557bc4da7e94d325a332638e2a22d4b3bfcdc5463a8aa332d41cb827b55f84e1722b3a0cb363b5690f963c5265c50d56da8c7bb71552f46231569870a2a1ba4c8c1a48a66438cd336d5931927029e2dca8e45519d8af127cebf5aecedd34eb6b7895ca6fe09ef5ca45193228e9cd6bc36933a2b842c0f4228348c4d1bed56d849848f700b8e95ce6a6b1b9f3a21856ede957e6b3704f98e898f5359b78c3608d4e40a024b433c8a4a7914d34cc44a28a5a04140a28a005a4a05068012941a4a280168a28a004a70a6d28a005a72d36940cd00069294d25001452506801c0d2520a5a0069a4a534940051451400b451450014b494b400b40a4a28017a1a53eb49450028e68e868f714bf7beb400847714a39a41c525002f4341e68ce681c1a004a5e941a3391400500f1494b4001a3ad1474a004a53452500145145001494b45002514514005145140051451400514514012d068a2800a28a5ed4005148296801318a6374a7f5a42050022f4a5029bc6ec0a7639a005238a8cd487a530d000869d4d1d69f400d34da79a6f7a0078e948694507ad003681451400b4e0d8a4c518a0071008f94fe069841a514bbb1400d079e697183463e6c8a711919a006d4d126e1cd415343214e9de80237183834807152b8dc78a681c5002c2c50e41c7f51562e88f2531d08a86319e4751535d63ca8f6f4c53016c08f3541a918b79ca07f7ea1b6389148ecd5698813f3d035023366056520f506ad588dcccbea0d4776b898fbd3b4ff00f8f903d45005eb4e5197f1ab21711d57b5f95dc1ab3c98f0319c55015187c99aaf3e08e3ad59c7eeb1ef54e4e2420fa714302b38dae09ef42b6d2452cbcc61876a8db920fad48cbb6c0346ff00de1d295dfa38ea299692059403fc5c53dc856718e4f22811330ca707e5719a815b63834b0392813d0e4545370e40fad3035206594a83f4aa3343b2775f43c53a190a952a7deacde2860b28ea7ad0333c9fd2a361cd3dc60923a1a6134804538eb53c4df2d577e18fa5490b0c119e6802c29dd91ea2a35c83914a99271e94abf2b1a008a7048cd57ab372dc5561cd00390e0d4c3ae45423ad4a0fc80771480732ee19155d860e2ad21278ed515c465483d8d30235e2a546c5442943605004fb72bcf5151e3069d13175c0193411eb400bbfe5f7a6ab7a75a46e3ad333e9401763be9923d9e636cf4cd68c57325c589497e6d87e573d47b56347d327a55fb4d49a0b492db6878e4f5fe1348d212b3268db0c0f1c52cd6fb94f9632adcfd01aac8f919eb57ed65ca6dfeeff002ef48ddea8c9bbb2960f988c8f6a4840238e0d6dbc4f216deb94c6dfa7a1acc6b72092a3907914999f2d8b16777c18e5191d3e957a38fe41b4e548acaf24b8f94e1c7435634fb978dca3804f7152c669c71600ec29f8c1e3a52c5207c600029c546723ad2191bfce36761d6988bc902a5e87eb4a98079a00722e38a865cb82aa3bd4c096e9f9d0100a04441045081e82b2af64ca935a97926c88fbd73d7d29c1a684f62893ba426953ef5460f7a91467156645cb61dfdeaf28c9e7a0aab6899c0ab9270a40a966b15a0420c8c588f940c0a65c45c28ee6ae45163083a01cfd691d03cac7b28c0fc6914642c58948c558f2cc8bb88a96ee3114aa47715246e71e594e14904d5058ce58f12fb0ad18a499ad36206da873c554032e4f6cd69e8f751db48e2638571d71de994674904d231015bf1aab3593052588c81d335d4df69e2ed5a4b794838e003c1ae72f6d66b772aea47bd04bd4c875c36298454f2afcd5195a662d1162940e6a478f6aa9f5e94c039a0910f5a4a730a6d02014514500251451400b4945140051451400e14a0d3453c0c8a0043494b4d340051451400504d148680034945140051451400b4514500145145002d1451400b475a414bd280141ed4743475a33400a791480fad27434e3c8cd0037a1a7704520a3a50014114bd692800a28a2800a28a28012968a0d00274a5a2928016928a3340051494b4009452e28a004a5c5145001451450049494669680129452519a0053452f6a403268001475a0f5c51d2801a477a5068c669bd0d003fb534d381a69a004a7a9a61a72d0029a61eb4e3c537bd0049db3494e5e98a4e9400da414a4525004cac1861a9a57069ab4f56c70791400d2a4734d3d2a66fb981d2a13400a879c1e86a42bb5b69efdea1a786ce3340098c353c8dac3148fce1852820a7bd003c926942828477a8d1f2706a5c629811c64ac9576f976a478e8573550a9dc31566e492caa7b2d004101c11f5ab0e77486ab270d53c8dd08f4a044339ce09a5b6ff58ac3b1a64cd9a48090e306803491f073ea6ac21e01f5aa487e439ea0d59c1d9f91154806bf43546e8e25156cb8c67a8c552ba6dcfb80a4c0187eec81dc5571d315663e462aab7cb2107d690c9226c11ec6aedce088e41dc7359a1b69abd01f3adf693ca5021a331b83daa5b90a591d7a118a8a563e5e3bd22c9e641b7b8e45003d46c62bf88abb0fcf095ea6b3d9b722b8eabc1ab16b71b255cf434c6473a6de3d2a0c7cdcf02b4ef630ff0032f4359ecbd45201ac018c1fc2a243b5a9e0e148a61a00b01f078a7138606a043f2d3b391400eb850578aaa38ab40650e7d2aa9eb48078a7a9c8a897ad4a98a604b19c9a9da3df11cf4a813e5e95389085031914014c8da48a4c5589172738eb51b478191d28022dc54fca714fdfbce4f53d69060f5a4c639f4a00793c153f85463ad4acbf26f53c5439e73480995f8c763483d33cd31704fb1a956079195546493814143e1660769abb6f21491587e229eb60f67b4dc8003647d2aaa9f2e42a7b1a46d07a1b7e7304da8370618ff0a86e2328e926305861c7bd32d66195c76f5ab2ecf70594a60118cf60c291440b003caf0690db07390712039a9606dc01ee38356540639c61854b115e12472321875156e3903f5eb5194c49b978f514e0a07238348091867a537049c7eb4bbcff0010c0a70233c5003946060523b05193416c554bb9b6a9f5ec281156f66f31bd145615f4997c0e95a9312232c6b0e562f2126a91121455845c203eb50c2bf373567ae1453251a166b84cfaf4a9d57749edd29215c271daa7b64caeef526a0d89c0db9a48d30067a96cd3f6e4a8cfb9a13a9f614014b525f941c7435243322a12572594114b7685e234db2282146931f29da4fa66a9015ca7eecb8fef629d6f10964546380c719ab0e8a217dbd0f22aa292bc8a6688bca25b16e6e100ce0ae7345d6ab6ef6ecad19918fa8e2a36d3aea661b50b06c10c6a41a04c40f31957e9cd325d8e726405890302a12b5b3ad590b368d54e411d6b2caf1419b444412071c0a8587cd5710e1482b9aad20f9e8326863af029aa33523f2052014c4447ad14add69b4085a4a5a4a0028a28a0028a29680014f078a653850014da71a4a004a2968a004a434ea7327c808a008a8a28a0028a28a002969296800a28a280168a4a5a00296928a005e947bd145001d45038a0d2f5a00523b8a073429c5068013a1a53c8a3ad25001450452d0021a28a2800345145001475a4a5c5002518a5a5a004c50294d2668014d3734668c5001494e0bc52e2801a073453a8a0001a7019a8c714f0714005028a2801739a33c520a2801c3d4d2753452818140067151be6a41d691f14008a7341a6a9c1a791400da55e0d145002b75a61eb4e6eb4d3d45004a0f0286e942f40283e9400943019c8a29a4d0028e297349da971c5002eec5280187bd329070680108c1a514139a318a0091307834d0086c52af1521f9d40ee3a1a0089d48e6a48dfe5e682beb4d036e45302c40433806a499b74adea38a82d8e241c54ea9972c7d79a044038352374fc296750afc7dded48cd851f4a065563934a990c290f248a7274a00bd161d883dc55c04671ed54602032b5591cb01dcd311136d11f1556e7a022ac4d94247ad559b263a180913fce0536f542ce48efcd314e0f1d6a4bb3b8237b6290cae79ab36cfb5867a1e2ab669e8d83480b528c122a188ed6352b10d186ef509e0d30244f95883d0d2f28403d8d20f997de83965ce791c5006a45fbc8c0cf6aa1329490ab0a7d94a72067a1a96f63debb87de1d6802830c1a8cf5a91f9151b1e6900f43814e535129a706e280252485e2abb1f9a9dbcf4351b75a005a729c53452d005888820e6a656000aaf0d4e064d301dcb0db509c8c8a9b24720f351c8d93cf7a00888a69a793dfb5364c638a006ab91c76347b76a683cd3c73d690c23f95812323b8ada95ade1b68a48befb7503f9d6428c1f6abd68617fdd4f91cf0682d22591ee6fd91092e3b0a8afad1acca0639661f95589675b4ba02dc86551f5a64b2cba9dd0dc00e3000e80505a23b4976b8cf20f06b552e8ac6576924f1f2faf6ac531b44e41e08357eda60c54f706916580db27048c090723d1aad2fad539a61705d71861cafd475a96094ba0200f7a8622ce69cbcf07ad34648ed46c24fdea40494c2c14f1c9f4a0ae3dfeb4a001400d24f56e2a94bfbe9bfd95fd4d59b87c0dabf79bf4a8081147f4e4d023335597620415928b939a9efe6334c4d3225f97eb568cdeac747c102addac7be7048e07350c299626b4ac61dbc9efc526c691662e22c9ab5126c455f41502aee2476cd5aeed8fa549a0e51d4d227fab19efcd2b709ef4b8e147b50046cbb863daaa5aaab19626e00e7f235a00715423c26a3f31c06383f8d52045a9635036ae36ff8d6691838cd69792121dc1bb1cfd6b3e61b643e9d6997134575968608638d01651c9354ee756ba95b86c7fbbc558d26c22bd593cc62194f6f4ad05d3ec200c6420edea49a60ec72f72f34ca3cc2580ee6aa95e6ba5d466b39a2315b800e323031580579a056b891ed00922a94832c4e2b4571b6abbaab8723eb4194d144d2e3834e2bf362971f21e28332b1a6d48578a6532428a28a004a2968a004a5a4a5a00514b494b4005253a9280002929c29a6800ab9668268de33dc7154c55ab193cb933401524428e54f514da9ae5bcd99980ea6a1a0028a28a005a29296800a28a2800a5a4a280168a4a5a005a29296800068e9450280168a3a51400b8c525283da822801296928a005a4345275a003ad0052814b8a00314b8e28a4ce2800a09a42693ad0019a4c5382d2e280100a7628a4a005a4a33499a005a2928a001852038a7939a691400b9a514c1c5381a005eb4bd05267140e680140a2827b51da800a00cd1d68a00630c1cd3b391432f148bc0c5002f7a4ef4a4e7a514001a691cd3e9a7ad003d3ad2b0c1a414bd4500369b4ea41d68014529e7a518a0500262834e0334d340094eebd69829e3a5002ad1920e295691fda802443c61a95d7e5cd351b7a6dee2ac47ca608c9a6221b423cce6af40a253201eb9aa71a624cfa55db75000907193834c08aea368c61b1c5573cc60d5ed419645ca9e71cd6774143018579a17838a5cf341c8607d690c96327a55c07ee935410e0d5b493214508074c7730354e6e41ab52e40e6a9c8793430231c9a918ee831fdd3512f0d522f520f43480829450786a05005889b2854d04e6a10715229e39a005438fc2a47f9be61c67ad42c79cd488dbb8a00236d8c0e6b415b72e7b1159d20da791562d65e314c08e64d8c7238aac7a55eb80197dea9900139a4032941a4a33400ad4c34fea298680141a75475229e2801f1b60d5a1cf4aa79ab5030287d698121c11c75a849e706a51cd44e2801a06067b530f3520381ed48402280212b839ab110565f7a858f18a58bef0e71486899d4af229c878ab0ca190639aae46d6c5236487afce71deb422b7f2a160ac44e46703d3d29ba545134c1e57550a3201ee6b5e2b8d3a39fcc6db961ce4670682ac73ee19c1627f1a484ed906e35b17f71a74c8c89853ce19571cd6231cf2281a359674f21c6df9fa8fad241208e7c74471b867b1aab6b26e2beb56649126e106197e61fd6901a087814ecd57b7903c6a454c0e454087669188029090075a68ce726900cc658b1eb54f5194456e7deaf39033589ab3ee60b4d09996e0b37bd4ea840145ba167e4558319dea07535445858232085fa56ac0bdff001aad6f0fce4d5f8530a4d4b2d0b12ed6e7eb52a1cfe74d03934f41814862b7240f4e6947233f8503819ee69546314c42e38acfbe5d92a38ec6b4b1553514cc39f434d0d0e1117676dc76e4328fa8e6a9dd803663e9f954f1079a38c46c412bb5bf0a6dd4476367f879aa2a21a59cccd16eda6552a0fbd6943a70b589daea4043fcb580a5838da483db156de7bab9508ecee17b62994d1a336996d670b4e5cb1e704d738d8c9ad43677d70150ac9b01e03702abea3666ce6119e4900d008a71e082314f58578e7ef64510afcc41e845595b75685a6271b0834132462b2e2434a57f7553ccb8909a611c523168a8ea42d57abd2afcb550ae2990d0d028c548899229ed090e47a531106da08c558f2c83834c963c1a0443452e39a280014b40a53d2801334a292941a003b534d38d34d00029e99ce17a9a60a92238914fa1a009a0b66c92c2a2b9b7f2ce57a56fa44bb4714c9ac5255228039ba2ac5e5ab5b4841e9d8d57a0028a28a005a29296800a28a2800a28a280168a28a005a28a2800a28a28016941e2928cd00146734673401cd0003ad2e294529140098a28e94d2680149c5349a3ad005002019a7814a052e28013a52e69283400869282692800a28a2800a2928a007d2934945002119a4069d9a691400e14b9c5301c5381cd0028a5ce4d071da97802801280292968002734c6c834f079a6bf34002f4a776a8d4d3c74a005a61eb4fea299de80245fbb4a3a527614b40084629a3ad3dfb537bd003a8228145001d29add294f2691a801b4ea1452d002a9c1a7edce6a35fbd520386cd0046bf2b55d5c32865fc6ab4b1ff10e84668b798a1f51de988b0386cd4f62eaec63271bc1c7d4542c4104af7151c44a1e3a83914c0b728c29561daa8fddc8ad297f7d6e2450320722b35baf3430203c354b8250535c734e8893c548c17e95622c6063d2a1c8069d19a60493391806aa9e49a99cee20d40dc391400def4b9a43476a4035f93494e3d29b400e1d29e8783518a70e0d002e7939a01da6861c645333401742f9b111dea04251e9d6f295e879a59d790e3bd004cee4aeefceab4c841c8e94f8db8c1a7baee84fa8a00a9de9691a853c5002834d34b486801b4e53cd368140131c52a3ed3518345005b07d0f5a18f1cd4519cf5a95860734c06023760f4a6b1e7ad0d9a6f5a40069ea4638eb4c1474a065eb690b29dddea4950020f6238a82d86ec283d6ae3201195272472291bc0ad923814fc37a1a43ea2b774dbbb36b2c5d2c7e647c0257a8ed41a986a0b1da7ad59bab096da08e4752038efdab652e74f2fe6c489b906e236e3154b52d5c5e46d0ac63667209eb408ccb738900e99ad00d1089c9037f51598015357606572acc3383c8a40d125bc9e54c63cfca79535795fbd50ba08d9f24729f30fa54d03ee40c2a5925a3cd0c7039a68208a6e49ebd3b5488476c2127b573f72e64958d6aea33158f6af5359f041b98123a9a684c75bc45532475ab56c81a4662338e053a450a140e82ac5b47b5791d79a007c51855c0ee79a9d06d400f5a4ef4f6e948634fdec7b548a09029a832c7e94fcd0018e714e51494a29885a86e97742c3daa7a6b8e39a680cfb391a3858a72c181c7d78a9a60ecadbc609c8feb55ad894b974fef67f3ab4d334d862bb540cfd7d6a8b467a7decd746baa5a5bc31929f39507815ceb0d8ec3deafa42b7162b209156488e30ddc532dab9a17faaca90c724708dae33b8f6ac8d4677bc861b871c8ca9c532e2f279c796f27ca3b0e94fb9b887ec496f102483b8b1f5a012b1414ed61f5ab4d0ee89f93ce463d7d2ab01922ae9cc9b163e0b60fd3140a4675e01f29f6c1a8074abb7f1148f6b0f9958e4d5288138148c58932f02a9c8b86205693a64d559d7e5381de821a238622c455964f9cf1c9e29d6b16768f51567cac374ef4ae09156687e6071d4e28b9b61b063b0abed0ef0e17f84e694445a1248e87145c7639b75dad8a31c558bc8f64ec3dea0ed5466c6d14519a621296947229280149ca8f6a69a5a43400829e3b533bd3b3c0a00e8ed5b7c087daac0354b4b6dd68bec715745022bdedaadd40571f30e41ae6e58da272ac304575c0566ead60244f3507cc3ad033028a523070692800a28a280168a28a0028a28a005a28a2800a5a4a280168a28cd0004d1494e5140005a7629dd28cd00252668269ac680066a4eb40e6940a00141a70140a5340052519a09a000f4a6e683494005149450014518a5140094529a2801d4514a2801314a28a2801ac29a0e2a4e298c3d2801c3919a05341ed4e06801c462933472690f06801d4b81b690631450046460d381a47148a79a00907dda6d38fdda6d0048a3341fbd4aa71480649a0053cd4669ebd69a473400a3818a28ea68340076a69a7537bd0028e29e7a0c5300c9a7819340080e0d4847151b0e6a4c9c0c5003e2f9a22add474a84a6da7a36d9949e87ad2ccbb5f3fc269882138539356630b247c0e6aaf40454969380c549c5005bb3984723c328c86e86aacf19473e99e29f303228743f32d4ca44f6ac7baf34c0cf929233b5b34f9061aa3ef4864a795fa5229e69ebc8a8fa35003b90307b544c7e7cd4ce6a17eb48061eb4529ed494008693a1a5a4a0029d9c800d274eb450048a7820d467ad2a9c9a1c50008706a6ce4557a7a376340120e2a48dfe6193c74350f24d3850024c8158e391daa2538353be192ab9a00737dea43499cd140086929c7a536801c0d2d341a703400f53835302197af3505394e2801e7ad0052373c8a1724d00481734d74c5598577a8f5a7b4191d295cab1560728c306b52d419b96c64751598ca6361c55d8dd8c6187503141a445923dac48e84d35464e09c03562404c6091c9aac7ad06e9966e616b4876311bdf938f4aad6a8d24a117bd3a795a52bb8e76aedab96904b146a5616677ef8ed486417eb124f885b2b8fd6a381be6c6719abbfd8f33bb7ca42e0907d6b3f051b18c106811a5088844cc7ef0e71ed51c27c994a03953ca9a644049b413c1eb4fb840806c3caf23e94992cb63ae69256dab9a8a19b7461a9933e0163f85492557ccb3f3d054d0a64838e0734d854aa331ea6a78012a690015dec07a9ab98c1000a8625ee6a7c500281fad3ba0a45c0e29d40814704d38522f1f8d3a80014a2929453017341e94514019939f26f55b031906ae348a57ca030d923f03553515c32bfbd588a48fcbdec7964073ee2ad148a57036c809ee2a4b5b57bb2cb17de0338f5a4ba5dcaa476effad4da44e60bd52bd58114cbe8598f409db06465507af7356bfb16282190962efb4e334b05f5ecf7688c85573cf1daa4bed35ee0f9904edbbd09e2826eee72f8218e7b558b7908c153c8c8151dc44d04ad1c830c0f229d6bc13ec77505bd85b8592459bcc182ca197f0aa36cbf31ad69e56924442b85048cfd6b3ad57175b4d2664c94c632c71d055610960df535a45786f53d28f2826d5f6e6a49b10da5be2256f6a9845fbd41f8d59b64c40a0fa62844fdefd0520228d304fbb50c9b778038c8ab213e6149247b89c500737ac47b67271d6b3ab6b5d8c8e71d00ac4278ab4652dc6d253a90d5122519e68349400b45145002528a4a05006c68cff23ae7a1cd6a03587a4bed9f1ea2b6d4d00480d04065c1e9482941e28031356d3fcb3e6c43e53d47a564f4aec5943a904641ae7352b236f29207c87a50051a28a280168a4a5a0028a28a0028a28a005a28a2800a29295464d002a8cd48062803028a000f14d268269b400139a4145380a0050b4ec52018a5cf14005251484d0019a4cd149400514678a2801297ad1450014514500145145003e8a4a5a0028a28a00281452d0031852035262a361cf1400f56a46a4538a71c1140089cd3f18a881c1a90500230c8a8c706a6278c544dc35003fb514750290d00483eed2f6a68e94a6801283477a5ea28010528a0fa52f6a0069a4a7374a677a0070e94a38a4f6a5ea71400ec647d6953ee629075029fc034c434f41ed533bef831e9cd40fc5390f3ed400d07e4e6a30406a9a45da78e950b0a00b719c8c8e86a581b6b907a1aab04a1081524d9dc185002ceb8aafc0352fcccb50b0c5032cc78d80e2993e0b295fc6991b12314e6fbb8f4a006e7b546d4a4d25201a6928345001450692800cd2834945001de9d9c8a6834a280128a523d29b40128e99a7c673c1350ab638a7f46f6a007b822a07fbd560b647bd42fd2801945149400b9a6d2d25002d28a6d2d00480f14e5a8c75a7a75a009554d2e08352463f2352ac3ba914909064723f1abeabbd411dbad558a3f29b24123b8abb12ede9d0d4b668910dc5b82b91505ab6c930dd3a1ad22b95aa13c2637c8e9426522da8677f2c8c819e4557b94dad903029f6f3b2a12067039a91ff7b0e48e4d5168a9132ac8a5c6541e456c36be898f2e1381d89ac46e09149d78a451b0de2191bee44a3f1acc99ccd234846371c9c74a20b62ff337c883ab1ab12cd1adb18625c8ce771a06416ef86c55d48d5959c9e476f6acd0706adc44c836e719a0962c6c23729fc279535248379029b710f968141c95e47d29206de01ef52c91f20e140a9e15212a1eb56633802a443c7029e0f15131e29fdc5004829d4c1c53a801694520a51d2810b4ea68e2945301d41e945250054d4537407daa1b064689449d1188fcc55d9977c6c3d4565da0cf9b19ea471f85521a2d5ceddbb5390075fa5534728e194e083c568bc0b1aaa83907f4cd669043107b1aa3446fff006fa7d9cfeec89718f626b2adf50b886426390f273b4f22ace9b696cea24bb6c293851eb53ea1a60b422e2db250727da80d0ccbf91e798ccf1942dfad456e71328ec78ab97331bcb5f31c0f323e09f5154578607d2828bb3ce16db691f3707eb54dd7cbbf0474241fceb421f2f6b1900e4e3f03cd51bb19114838c8c1fc0d2322f471ee624fad0cb9918e3a71525b730a9f5e68d9bb91df35248f886147d29703793ed4a83a1f6a503e6348420e58914a4500609a5a00cbd621f321661d8572e7a915db4f1874287a115c8dedb9b79d971deaa2672455cd1487ad02ac80a4a534940052d2514001a0506905005ab06db7287deba0535ccc2db6453e86ba38983a022802614e14c069c2810ecd477302dc42c8c3af7f4a90538500727776cf6d31461f43eb505751a859add4278f9c0e0d734e8518ab0c1140c6514b49400b4514500145145002d251450015228c53545482801714c26958e2984d0004d14514005385345385003b348682692800a43451400945141e94001a05145001450297140098a0d078a693400668a28a009696928a0028a28a002814502801690ae6973450046c3069c39a52334c1c1a00561834e0734879a453834012003bd4720e6a40334d905002034522d3a801569c7934d5a5a003bd387ad341a527028001c9a3f8a9071cd2f6cd00213cd2514b400a2947ad25293c6280133ce6a453b87d2a3c8a729c62980ade94c078a9e4002838ea2a03c5004a0864e4f35132f14aa71c5382eee3340118c0e9d6ac236e4c1e48aafb714e562a41068026048c8a8a51cd485b70c8a8cf22801a8d834e901073eb51f4352921a21cf238a40454a683476a0061a2834500291c534d3bb534d00145140a004a05291499a007034d3d69334b4000a901e2a3a506801e1a83c8229b4a3ad0047450dc352500145145001452528a005a7034da2802ec0db8015710f22b2e072ae39ad341b97352cb897d220473526cda053613940d523608c541a883ad477116f8fdc5483d29dda8032e27f2a4c1e9dc55a32e76a638ed8a82f62dafb8516d274dc32579fa8ab284b84c3668b39960b946750cb9c303e94f95fcf048181551b238a0a4756f6d6378a02b2e31d14e2abcba0215fddcc47d6b16d21966388cf4f7ab9f6e6b24288e5a423939c814058ab7d66d65204675627d2a385f0dd6a3924695cbb9249e493480e0d0334510cadb8b7dd1d2a2c08a5f94e51b91491485938383523c0c215c9ce791ec7d291048082454c0d5481f2b5615aa5812e78a553c5479e00a721e2908945483a5479e2941e28024045283c5463ad3c5003b34a3ad369c0d021c38a2901a5a60358706b273e55e1cf735b18e2b27525db3861dea9022da44e22dec490011c9aa730c4a7df9ab6ad238f97952a1c8fe955ae47208edc5517127b78cdd5bec4c6f8ce707d2b4f4dd453c936b76474c026b0e10eefb2227711d077ab1069d732b0c44d8f53c5053b13ea3f66b78da2b63b8b9cb1f41e95995b70685217ccec36e3a56348852465ee0e281a65db60ae8bbfa63bfb1a8ef634f2dd50e42303f98a4b4f43d8e3f3a9e6b611a300725e33c1f51cd043dc2c5f36aa3fbbc54e8318fa553d38e43afd0d5f0304543218a9f7452d201814a29084a283487a5002119ac5d6ad372f98bd475ad9cd453c6248d811d453426ae714e39a655dbfb7304a4553c60d6864c4a0d1450212968a2801281451400a3ad6f69f26eb75f6e2b06b574a9328cb401a8a6a406a1535229a044829c2980d3c734c070ac8d5f4fdea6689791d40ad8028640c307a1a00e28820f345696af606de4dea3e46fd2b3690c28a28a0028a28a0028a2945003d45389a41c0a463400d27349451400b45252d0028a5a4a2800a28a4a005cd25068a003b51474a5eb4009451450014138a5ed4c26800268145281400628a5a2801f45006052679a005a2928cd002d145250028a5a4a280169ac29d41a0068e94de8697a1a57e6801c0e7a52329c734d438a7b12c28018b4ea68eb4eed400a294f4a414b40051d4d14e038cd00368a5a414001a179a0d03a50028eb47bd1da90f4a003bd00fcd476a318a00b119de3d71492c784dc3b1a6dbb6c6fad5898e206523a9069814bb834f5273914c14a0e0d201d2a746ec6a339c54ebf34641ea2a26183ed40021c548d512e335276fa50044dd69cbd291fd6846da68003499e29e0678a8fbd00069b4fed4c3d680141a4345140094a28a4a007534d00d0793400945068a002945252e6801734a0d373403400e939008a8ea43f77151d0014514940051451400b4b4da5a0070ad0b49372e33cd678ab56c763d2652dcd6b790a1c76356f8354223b866ad44f93b4f5acd9b225c0a5268e9d68cd03229d448a462b38e62938ed5a8c6a95d47cee5a680952541014c67774e2aaccbdf1440d9c21f5c8ab32b24878e3daa869952295a26ca1c1a6b1c9eb4ac30d8a6d0505028cd25032689f691e957079939501b8073f8d678e0d5ab797a0068131f2298df70e01383f5a951b34811a4472ff0075bafb7bd45192a4a9ea2934496c1e69c38350a9a914d408941a78351034f5340128e69c0d314d3873400ea70a68a750217bd28a414a0d3016b3f545cc60fa1ad0aaf7d1ef818534056b39985b020720ed3fd2993a1f2f73753827f95374f7dbbc6338c363e956267594b6d071d3f3156522bd8cc20bc8e4f43cfd2b66e7c43b1cac31eec7726b9ee47e15b16da21b98a3944a155d73d32734cb7621975abb93a3ed1e805559999e56790619b9adf8b46b3806e99f763fbc7159dae7925a27b660571b7e5e9c5204ca36dc48403d467fad5fd8c584d92555ba7a0359b03ec950fa1e6af9f39e2f2d3a60e7f0340a456b4fdddf143c72462b53ae2b327263bb8e4fef61bfc6b517a54b21852538d36a4910d21a75348a004a434a7a52500656b36be645bd4722b9c75c139aed2550ca41e4573baad9989f728e2ad33392ea651a4a7914c23154405145250014514500157b4c936cd8f5aa353da36d9d4fbd007402a45a894e40a91698878e4d4838a60a7af22801e0d394d305380cd02197102dc44c8e3ad72b7b6ad6b3146fc2bb255c0aa3ab59adc41d3e71d08a06727453e4431b9561822994861451450014e5a6d38500389c0a6134a4d25001451450014a2929680168a4a5a004a2834940052d252d00145145002d274a2909a00426928a5a00052d149400b9a2928a009a9b8a751400ca29d8a36d002514519a0028a292801f40a6e69c0d0023fb5341ec69f8cd308c1a004fe2a937714c3d29548c500277a5a43d696801452e69074a51400bde973c629051400a4521a28a004ef4b8a4a776a00293a9a297a0a0007268ef40e28a0001f987b55b9183400f7aa80639a783f2e334c0887dfc53a41890d21186cd0fd7f0a40394907341e0e0f434d524d388f973e9400d23069e3914d1cf14aa307140030c8a8c706a6a8d861a80157ef0148c30d4b9e869663b86ef5a006534d19a4340099a2928a005a0d1494005145140051486941a000d2529ebc525002d2668a280141a4345079a004a28a2800a28a2800a514945003c54b1b7350ad48290cd4b47ce055c1d7d0d65dbb630456944fb9467ad43368bd09c39239a5ce6a3a702475a450e2715138c8208a7e690f3d68119b2031b93e878ab76ee8ff3360647eb4db88c329c55589b612a7a1e2a901627556194ed55eae10821183f37a554954ab7b1a652637ad252d2671415717269d1b10e08a62e49c55996d648a28e4653b641906802c07629b509dadc52dc5bba057eac073ee3d6ab5bc855b19ab61a49645607381fe45048c47dc054c0e455523cb908ec79153ab7152c44ea78a7a9ed5083e94f53935204ea69f9a894d3c1a007834e1d6a3069ca68025a514c069eb4c42d3251b853e90f43408c6b73e55e153d3383f4357d8a790801f9d57047d2a85ea98ee811c66afaa230321c03807fc6ad1667c83f7adf5ad282e2e9b4cdb6cc418d8e42f5c1e9fd6a8dca6181f51835269d7af6770197054f0ca7b8a65ee80417570d822476f7ab57d67f64d3e2493fd6339623d38ad3feddb458f700d9feee2b12f2e66d4ae3217007dd5f41402b94c1ad3b7b8daa582eece0e3eb596dc75abf62e36ab11c2fff00ae809115de4c31b63054953fceb46ddf7c28c3ba8aab76eb32ca100c0c30feb4ed35f3063d0e2a599b2ee690d028a9244cd2139a08a5a0069e9494ec5262810c6eb55aea0134654d5a34c6a60725776ed0c84638aac45749a95a8950b01cd73f2214620d5a666d5880d14e614da6485145140053e238706994abd6803a488868d48f4a956aad8b6eb653e82ad0a622514f5e2a314e14089453c0a8d73530e9400668ebd694d20a00c5d6b4edc3ce8979fe21580462bb9650ca41e86b9cd634c30319631f21fd281a3228a28a430a5a4a5a0028a29280168a28a002969296800a2928a0028a4a280168a296800a5a4a426800269b4b49400b451450014514940051451401352d251400a28345140098a434e349400d3452d2500029c39a65283401276a6b2f14b4b9cd00454ab8cd0c314def400add681431a16801fda81494a2801c68a051400bda929693340075a0d149400a3ad2f7a4a5a003bd0393451d28017a9e28ef483a528a00732e578a8cf0055843f2d4078245003326a68ce460d454e56c1a004652a6941f5a74b96018547cd004a689571823a1a10ee5c7714f61ba2c7a50057a5c6463f1a6e69c39a008fa507a507ad250014945140051451400945149400b49451400b45252d001451450018a29c3a521a006d14514005145140051451400e5a9a3e4d4482a68d483914868b11aec23d0f4abb09e45574c3003b54f19e31dc54335896c52e78a621c819eb4a69162e6933494500230cd51b88f69c8abd514c9b94d342208d83ec0dd8f3f4a967452485e4553198e4ab90a86c9cf6e2a82e553c1c1a7471b4870aa58fa014e9940191d68b4b96b69d644eaa699573774bd184789aec0cf509e9f5a6eaba8c138fb2a2e541fbfe87daa1bed5259dd3ca3b21247e3f5aada8c96cf362d9303392def40151d5a372ac0820d5ab798aae41c1a4d42549e54f2d79540188ee6aaa31460681974c6f2a963fc473f434c462383d454ab396836263078e692e6164c3b70e07cd8ee3d6a592391aa553559183007352a362a40b20f19a7026a256e29e3a52024069ea7151834ecd0048a7352035129f4a78a0449413d690514c465eaabf75876a7db2f9f0c7c9ee0fd3ad4ba8a6e8091d4554b0908460bd4722a91489aea321581e4af354fbd68bab60efe49cfebcd67ff001d51a476248e179dc2a024d68ab2e99146f105964724337618ea2ae69a74e483609019187cc58e0fd2acb69b6b35b98e36c296dc0839c5027239594e5d9b18c9cd58b471ca9f506ac6b566b693a0439565fd6a95b9c4ca0f46e2829ea8d19846191571970538a834d7c3b27b66a6d89e479a4e1d486fe59aaf1e22d44af405881f8d266469f6a28a2a090c5252d2500069334521a042114c614fa461c53021750cb83585a95a609602b798555b98c488450989ab9cb5308c55bba84c521e38aae45686447452d2500140a28a00dbd29b3063d2afe702b2f477f95c56937229887c4dbaa502a38976ad4a2810e5a954d442a45e94c07d18a414a2801d4c96259a328dc8229f4500723a9d8b5a4e401f29e86a8d7697b6897501461cf635c95d40d04ac8c3a1a91905145140c28a28a005a28a2800a5a4a2800a4a5a4a00296929450014b452134001a4a292800a5a4a5a0028a28a00292968a004a2968a00968a29680129681486800a28a2800a4a28a0042290538d34d003c734e1802a3069e314008c3bd47531e4542dc1a000d2ad369cb400e34b4def4e1400bda969052d0014869692800a2928a00514ea68a7678a000519c9a43c500e05003a90d03a51400f43ce29d2601a8c1c1cd48eb98c9a00809e6929720d2500488770db4c390706955b6d3a4248cd00351f6b0ab6a32bec6a90ea335a70c5bd141ee38a00ce9570d4ce956674f98d5734008dd334da534da0028a28a004a29692800a28a280128a29680128a5231460d00252d18a050028a5a052e2801a4536a42b8a4db9a006514118a280014f55a68a963193cd00228c35598c631e8699e5e0e6ad46bb96a59490e8d38e2a6453d7bd24631c77a94549aa1cad8a76690514862e68a6e6973400a69b9e2834940156e63ee2991499f949c7a55b91772d50914a3f1d2a908baf129854e7248e6a9b2ed6f6a9e26f30819c7ad2dcc783f29cd50263ed2e225531dc2978cf231d41a48e092e9cfd9e327be3d0554ad4d36f4da59c8d1a866dc339f4a0a08ae24b0cc525b805bef6e1c9a82e510624887c8ddbd0fa56cc37967aa4612e1555c7af1f91aa5aac505adb2c11bee72fbbe83140ca304a54f5ab8a65988e8703bf7f6acc1576da6231cf4a4023a18a5ff64fe952a9e68f2da7de481827f2f7a8d77231461c8a9622c86f4a941cd40bd2a45393480981a78e7a544a69e29012a9a783518a78a043c1cd3a9ab4e269888a7506261ed591684c77457b6715b4e370ac4947957793dea90d1a2f2b3a0dcb8dbc1f722a84cbb656f4cf15a3e7af97823ef6187e354ee393545c5908191d6a6866923fb8ec0fb1a9b4eb55bb95a227071906b662d12da219958b11ea70281b6625ccd71750832e5c467ef7a66aaa93bc76c5749726c8dac96d0b26f619007722b9a340d3b9a51422652bb88073fad57baca491487ae067ea29f6f230886c3f31fe94cbb4610156eaaf9fc0d041a8a77a83eb4bd2abd9c85edd0f70306ac039a8205a69e94b41a4037b5149450210d369c690f4a60466a271d6a53513d0065ea36fb9720562b02a706ba799370ac1bf88a499038aa4cce453229b525348aa246d2529a4a00d1d21f1311ea2b5d86e18ac3d35b172bef5b8b9269889d7814f5a60a5079a044a29cb4c073520a6028a753696801c2969a2945002d666a9a68b88cbc63e71fad69d18a00e1a48da362ac304532ba1d6b4eddfbe8c7d715cfb29538352509451450014b4945002d14945001451450014e1494b400134da09a280128a28a002969296800a28a4a00296928a005a28a28026145149400b494514005253a9280128a28a0029b4b4500253969b4a0f34012678c0a8e415203e94d7a00845498c2d3075a7d0028e69d4d14ea00296928a000d251450014a2928a005a5a4a28016928a5ed40077a3ad2502801dd6a446f970698beb48a7e7a006b0c1a4a9245a8f1400a0e29eafc118eb4c18a33400701b9addb640d6f1b8fe1ac23862335d169a9bad1476c521a33efe3f2dcfa3722b34f0d5bba8c25a056ee8706b16514c1a213d6929c69b4082928a4a005a31453d0678a008e97ad39970691450026281d69e57238a6e0d003c80545496eaac4a9efd29d0c5bd7e94e1110c31487618d6e71c0a80a153822b550647cc39ef44965e70257ad171f2996a39a902d1e598e4da460d4ca9ed40ac344791914c31e39153c7f2b8f4a91e2e7701c77a2e3b14244f4a8b18ad0921c723a1aacf1502b10e2acc09b80a6227153dba956f6a18d22c247f2e0d110d8e41a954679a475e41a834b0e1d6a40722a31d29ca690c7e714e041a675a01a063b383c52669334668017349484d00e68017355e74c8cd4e4d35802314d08a4ac51aacc2a64c82dd3a66a099369cd10b9e99c1ed5421655c1a586531b73d0f51563ca2d16fcd5475c1c1a6522e5c34326c16a841c726abe093c9e7deac69f3a44ccac06594a827b1ad1d3748dce25bae0750beb40ca50e9b2cb68d381f779c7a8aaaac51b15b9a8eae901f2ad7048e091d3e9584cfbdc9f5e68197a29ce300f6a5963728ac4723a1f5aa51bed6eb57048f2054cf71cd20111f22a6539150dc46637dc063fbc29e872a2a588b0bdb14f07350a9e6a54352048b52035103522e68112834e1518a72934c429ac7d5176c81ab66b3b54883267d29a043ec995a342f8c636d4370b905874a8f4f3be27427a608ab9346a8a403c631545221d3e7f22ed1b38e719f4cf1535dc57864292991883c727045678386adbb0d71238963b9524a8c0614cb647a769d2ac9e7ce362202707a9e2b20fde35b37fac89e33140a429eac6b1bbe681abf52d5a3ed20fa1a965df26e2eb80c9c7d4554b76c498f5157a4b90c91aedc10dd7d8d04cb71ba6b7c8cbe86af0e2b32c8f9778e87b835a62a590c53499e28a4a420a4a28a0407a537b53b34d3400c6e0546dcd3dcf150b363a52111487155d2d05dcbcf0a2a60ad33ed1d3b9ad286111a00074a77224ce5352b236b27b1aa06bacd5edbed16e4e3e651915ca302ac41ea2a93b9230d369c692a809ec9b6dca1f7ae890822b9ab738994fbd747172a0d3132614a39a68a5068112a0a90715103c548a6980f14ea6d3b3400528a6d385002d2d25140032865208c835cceb1a718252e83286ba8151dc40b3c451870690ce168ab9a8d935acc548e3b1aa748614514500145149400b4a29052d002d2134134940052514500145145001452d25001451450014514b400514514012d1451400a28a4a5ed40099a2929680128a5a4a00292969280129294d25003d4d29a629a7668019de973487ad2ad003852d20a5a005a4a3349400b4525140052d252d002d149450028a5a4a2800a28a2801dd714743480606693ab5004a39a8dd769a5a737cebef4011519a318a3028016ba7d17e6b31ed5cbe3918ae9f4318b7c7ad4b2a24d7716e4618ea2b02683923a5751226720d62ea51153955e0d08a68c32b8245348ab2d1f05bd2a061546647494ea69a0029e870734ca72d004f22ee1b8545b4e6a7846700d486300e290ec44a871914d74e6ac42b86db534b065091dbad171d886d494e9cfb55b280f3f8d56b643b803d7a568a46aea73d4751499686a45950cbd4751562150afc74229b6ff0029da7a8a9cae3047e352328deda067caf7a85212bc11f8d69950d8a69881247e545c5633658769c815246bb938ea3a8ab2e991835011e5481874ef4ee162329c60556923c9c62afc8992197a546e991ef45c2c53316c1f5a588738a9bef2ed229153145c2c4a8dc63b8a56e951e707352039a431aa69d494b9a062e69b9a28cd030cd3c5479a33cd201e681499a2810ea4a28ef4c08e51b85523f2bd5f619aaf347ed4d087c72334780783d453e68b0a33d4d548df6355b2ed2955073815408abf74f35ab15e5c5d5a0b68db0c3a7a91e959f34654f351a3b2306462ac3a1141689258de272b20c30ea2ade9515b4d3b0ba385c71ce39aa05d9c92c724f7a290c9a6dab2b0439504e0fb5496f2fcc066aad3d7a7140cd20b24d20c7381ce7bd4473149b4f4ed45bce71c1c35486369558b723bfb504922b66a4078e2aa44c55b6355a5350d012ab5480f1508ed5329a42245a78a8d69e2988754176bba13f4a9b34c986e5c53031ad1b64c57a738ad0585fca25893fd31598e0c7787deb515a47dc07dce18fd2a914519502b9151d4f70b8209eb8c5434cd500268cd03b5005031d1b6d707d0d68831f94fbbae38fe75967ad685b2aca0063db341122190ecbd471d18035aaa735957c8100da73b095cd68db3f990230ee054b3364e28c51da834891b494bd69a680034c638a526a09a4029081dc62a0dad336d5071dcd3e389e76e785abd144a830a314ae4b90db7816240054a78a774c5318d066432f2a41e95cb6ab6de54e594706ba890fcb59d730acc8c58534ec2398349524c9b242b8e951d6a50f87fd60fad74911f917e95cd467e615d1c27744a7da98993034e1d29829e06681122d48298b4f14c0519a7034d14e039a005a7014d029e280140a280696800a5a4a5a00a7a8592dd44411f376ae4eead9ede42ae08aedea86a762b7301c0f9c720d219c8525492a18dca9182299486252d252d0028a0d1486800a4a28a0028a28a0028a28a0028a28a0028a296800a28a2800a28a28025a08a514bd680194538d25002514525002d1494500145251400521a5a43400829d9a6d19a0029eb4c1d6a41400b45145002514525002d14945002d1451da80168a4a5a00296928a005a4ef451400eed49de957a734d039a007f5a07148067a50722800619a6e29690d0028ea2baad2100b743ea2b951d45757a483f665a965c4bf2ae403e9556e205789b233c55d3cad443935259ce2c00120f42706a8cd16c765f4adeb8b7f2e5703bf22b26f918397c75eb54990d19cc3069a454b22f434d0b9aa248e957ad2918340a00b109ab9b77006a8c271d6afc0030152ca43150094678cd5b8d0ab60f391449064823bd4aaa7827b522ac5430b46c180e09e0d5b53c838c13d6ac4681e22beb9c5471af407af4a4317683b5854c9d39a8d3e5f94d48060503065ee283c807b8a01a0f4a4034804d413441863bd4e6a2739a6057898afc8d438e69665ddc8ea2a30c48c1a006b2e69b527d690d021940e2823d28a007668a6e68cd03149a43452500029c29b4a280169734da2801f9a339a6834bda8017a523aee14514014a54dad4fb77c1eb83daa499322aa60a1aa24d050d2824f6aad22ed3ed524139032304f4352c91931863de99499529682a41e6963c1700f426828558d9c8551926b51b4975b1f371871cedf6abf63676f63119e7656e320fa5676a1aa35c391192b18e8077a06505631be455c866664383807a8aaa91b48a580e9d69237daded40171a26280e7e95242fbb83d45468ed200b9e29f2a32306fe203f3a9622753cd4a0d578dc300454aa7352227538a7839a814f3528e2810fce6948c8a414bda988c4d45764e185685acfb2dd4e339e0ff4aadaa2e573e9469ae1e239fe1c1aa4521f3fce84e391cd56442ee14752702af4d872db00c118aa28c55d4fa1a66917a177fb2e75386423dcf14f86dade19019e553839c2f35b36d776fa940b1c8407c72bef59da868af182d6f975f4ee2804fb99170024ee14e5431c1a9ad8ef42bf85567520e08208a96d5b0f40dec58b983642e339c80dfe35634d7cdb01fdde2a12247219b9520ad269ac433a1a4cc99a8290d3734d2f5240adc5319c28e69af37381cd3044d2b7cd902909b11a5c9c2e49a7c36db8ee939f6a9a38150600a97a0a5721c840817ee8c714a0f028cd276fa522418f151b1eb8a7b542edc71d681114a72703f1a8655f9706a62bc9f7a8e5e8734c0e7f53836b6f1d2b3aba0bb8c3a118ac1914a3906b48b18d1c1ae874e7df6cbcf35ced6be8d2f54aa40cd70b9a7814829c2a843945385029475a00514bde8a4a007d385474e06801d4b499a51400b4b480d2d0014d3cd29340a00e7b5bd3f07cd41c1eb584460d775344b2a1561906b93d4ecdada7381f29e9498d1468a29690c4a4a5a4a0028a28a0028a28a00296929680128a28a00296928a005a28a2800a28a2801e1a9e0d46462901a0097ad04530353c1a004c52629dd68a0061a4a7e29a4500368cd149400b4868cd2500145145003853c53053c500145145002514514005145140052d251400b45145002d1494b40051452d00028ef4a38a69eb400e148c68141a004a073d69296801c3ef0aeb74a5c5aa7d2b928fef8cfad761a6ff00c7b27d2a59712e5447e5931530e951caa4f3e9525905c461c67b8accd421050301c1ad961f28350cb02bc6c87a37e9408e59e120106991a7cd5b325b7cc0918ec7d8d53b8b5304e13d6aae4d8ce9a2218fb53157bd5e9a3f5a81140e31c8a62b088b56add8a48011c546a066a68e3dc3dc7349948d15194fe54f45c0a8ed640c983d455851cd496361cab301d33c50106ecfad2c5c337d6a5db95e3ad022165ce0f714e0686e39a00e680169a69738e2909a4318d519a7b1a8cd301ad503af715313834d6a008b39a4cd388f4a6e68109484d29a434009452668cd002e6928a09a0029734dcd28a00334a3a5252d002d283482940a062d18a4a5a0046e955664ee2ad546ebc53422aa36c3575642d1803f0aa322956c8e952dbca4707a531264f346401918a80706ad348676031c81504a855b9a65a2496ee59e34476caa8c0157f4fd1daea1f31db629e9594a6b756e6692ca286d739c6091da818db7d3e486e6481f04153cfad64480a395c720d7536d09b1b3692e1f2d824fb573a6096e1d9d119b249e05031b6d2e1803570979dc01d077acf31346df302a47ad5ab69ce4293cd202564303e71807a8f4a9d48c0c53515a7662dd00c7d698330bed272a7a1a422cab7352a9e39a817b1a901a9113034b9045460f14ecd3115af937466b3f4c3b66643d0f15ab7033191588098eef00d3406c90ab08dbf7b033f5acf946d7357e388b167cf18ce2a95c8f981f6aa2e258b4b579a1f3a36036b60e4e315ad0ea896916db89bce3d820ce3f1ac08e67086353f2939c56ad8e8ad3c6b24cfb14f41de82994b53be8ef1c18e2098ea7b9aa9136d907d6b4f53d19ad53cd89b720ebea2b24718a07d0d1695846140e8739a8226f2ef7ae031ab10ce8aac4ae7238aa770732c7274c8069199a666ec393408e49393c0a961895402075a994726a1b39db228e150bd39a9b0001476a09a9245ce29a4e4504f349de81067a5048cd349e314c639190680076e98a6e075a777a61a0069e6abca726a6738155dcd302190645636a1161b7015b4fd2a8de461d0d5263316acd8cc61b85355d86d620d0a7041ad00eb51b7203eb520e95474db81340a3b81cd5f1c5310e14e14d14b4c07669690528a0029c2814fc5003453a8c5285a0402968c5140c6f7a2940e6834009552fed16e206047207156e83401c3cd198a42ac3045475afaf5a949848070d59152509494b494005145140051451400b45149400514514005145140052d14500145145004bb734d65c53f34a067ad0043d280d5215cd3597140006a766a3a035004941a6eea5cd002114c22a4a691400ca294d2500140a281400f5a7520a5a002928a2800a4a5a2800a28a2800a28a28016928a2800a51494a28016968349400b9a4a28a005141e2933413400519a4a5cd003e3fbe2bafd357f709f4ae421ff5833eb5d8e9ff00ea17e950cb897050450294d49646bd0a9a0af14adc3034eeb4c0ceb989b7164e7d45457110b9b5120fbe95a5b7e7e6a06410b923ee3751408c8118954923922a93c18624718ad53118253dd73c547343904a8a61628c69961c7ca7bd5908636c1ea29234c0d87ea2ac1532c6a71f32f1486400ed395abb136e1558a6d39eddea54ca918a064ca30ed522d323f9989f6a7e39a000a83d699b714ecd2668018fc734c278a7b1e2a124e7140035474e269a6801a69869c69a6900c34d34e34ca6025252d2118e68101a6d29a4a0028a28a042528a29050028a70a4a5140c70e9466928a005a334525031691ba52d1da8115e55c8aafd0d5c7155a64ee2a9124d6f36d2083c8fd6a763e7296c567a36dc1abf04c021f434ca4cacea41ab3697d35a1cc4d8cd23a6e5c8a83041e682d1b56b3cfaadc2c72b7eec72c074ad1bcbd86c22115baaefeca3b5626933b42eea846e75c0cfad6b69fa704633de302dd704d03295ec523d88b89f87278fa565ab61b35abad5fa4f8861c1553d7d6b392d9da269402557afb5032cdbdc10bc1c54d1c6d22316fbbfcab3d495357a195bcada3a11484d0f8988ca3f5152ab5452c2e103e47b1f5a227dc334892c8a767151a9a706a448afc8ac2bc3e5dc86f7adb2c0f158baa150dc1e69a11a70bb98d447c861b6a3bb5dc99e847351e9939580363a7356256f355cfa83fe3545c4af64a1ee6343dd80ad5bfd69d64315b615538ce2b1a093ca991c75539ab3776aca44e80b4527208a0d6c4d0ea5725f12b9746e083e9542e17cb9dd4745622ba0d396d0d847713040c3e5cb7a8ac1bf757bd95e33942c7140226b3dad8ddd0536f40c1d83856a65ab0e56a79e211c4ca0e772e6910f7342c9f7db467bede6a71d6b3f4a90183693c8357b38359b39a5b8fa6eec8a09f9a9b9e48a44016e28269a7d28c03da80019ddcf4a31834e230b4d6c13400ddddb151b9e29cdd2a263cd0031cd44c69ec78c544c6801add2ab4e320d4ec6a093a552199373160e4556ad499770acf9536b7b56880b3a7dcb42f806ba588ef456f519ae3d0ed606babd3e412daa11d862a909966968c5005310b4a292979ed400a3ad4abd2a314e04d003e941a6519c500494868078a280105211cd28e94b400da08a5a281952fad56e612a7af6ae5af2cdeda42181c57644d57bab54b988ab019ec6901c51a2acdf5b35b4c558556a4509452d1400945145002d252d250014514500145145002d1451400514514012d2e69a68cd003c1c521e6901a5eb400d2b4c231529c76a6914011d2834a569b400f068a6669c0d00230a6d3cd30d0014ab494e1400e1451da8a0028a28a002834518a002814502800ef8a0fa503d681eb400514525002d28a4a5a0075149da8cd0021a28a073400b41a2973400dcd1452d00496e034ca0fad76366b88571e95c85a8cce9f5aeced78897e950cd224cb4e34941352508dc8a453da9699d0d301d4d9543c6453b34dcf38a00a7731fcb4d8d0719e41156dd7729150a8c71f9500519e1d8c303bd3e23e5c8a4fdd61fad599537a63b8e950328f2f07eb40124b1861c54417076d3e272460d48579cd2191a8da73525358629172280149a6934a69a6980c634c34e6eb4d3400c34d34e6a613400d3c5309a71a61eb4804269a69d4d34c04a4268a28109451494c42d14525002e28c1a70a290c68a5a2968001452814a280129452e28a004a314b45003180a85c54e6a2714d08a6e369f6a96170081d8d12264542adb4e0d508d4de822dbdfb7bd4322927351c2f92037e156a42ae0051cd06899594953f29c1a9bed1338da64623d3351c8850d221c302682d17ac74f92ea5c00703a9ada9e4b5d36d7cada18b0fbbdcd410ea90dbe9c9b00f3318c562cf3b4f2b3b9258d03b0929469094185ec2a5825da704d403a519e690ec6948eee8173d4f149246f112f8c7f7b1fcea08676c053dba5580f24d2038ce0723d45066d109bb55ef50c9a80078351df59b79c3cbce1aa5b6d24020ca73de93326ec42d752ca7118273e94269b35c30321c0ad88ada38b8551530003000715372398cd821fb2bf93d548e2ac3c88cabb476e68bf4da51c763424686366ce0e6a93358b33641b6461e86a737f335b2c01b11818c0a8ee47cf9f5a873546e890c8de584c9da0e7151d19a4e45219340d86c7ad5c6472031395fbbf4aa111c38357bcd73185032073411219a6bec9990f7ad72d9c56344447a87a026b5c608e2a247354dc56273d28206723a50064734e18d9ef526637a1c9a7707a51ce2909a0033c62984f4a5279a8c9a00463cd42c79229ec78a89db9cd00318f4351934e279a8d8d301ad5039a91cd40e69a191bd559d72a4d596a89d728df4aa4050aded0e6db0ed6618cf00d60d6fe890836e5987f1715a2066b66949f4a4c52e2992343e0e0d48a41a8a55cae475a8e0725b06802d8a75228a763340094134bb68c500206a7e72298569c3a500029d4d14b9a00290d19a4340c4a5a4c52e68033757b01731975fbc0572ce851883d45772791cd72faddb88ae72a300d26346651451486251451400b494514005145140051451400b4514500145145003e8a28a0029734949400f068a66680d400ea6914a0d2d00464514e3498a00334d34ec534d0014e514829e3a50002834b4940051451400b494514005140a2801334a7d290514001a052502801d4b4945003a928a2800a5069b4a28014504d141a004a051450059b05dd749f5aec6dc6235ae474b5cddafd6bb08b85150cd23b12514519a9282908a5a4269808291a94d21a004cd413028c1874a9b14328618a0088fcca08aaee3e620d588b8250f6a258c3734015b6e3a5488d9a45ebb4d2edc5002b0a8ce41a7e4d21a431334c34a78a6939a60318734869c69a6802322984548d4c6340c611519eb525308a421b48d4ee94d34c06d3697345021a450052d18a620a5c5262971480514ea6d381a062628c528a28000281451400b4514500141a5a280194d61914f229add29888185569971c8ab6f5049cd34491c521e2b42d1d4b6f6fc6b29be56ab504b8208a634cd0b828ec4af4aacc8475ab76cb1ed25bf0a8e55ddf77f0a0d532b82451934878a3ad22c901e28a6038a7678a063d5f1572dee31c8eb59f4f49765026ae6816694b12303391ec6a7865de067a8aac93111100673de9159a321bf3a4d18c95cd11d453c8a89181406a5cf15998115dc7be1c5538d5a40369c71fcab45f94acc4768cb2af556ab89a4190dda953cf6aac6aedc2b14f9bae2aa22ef70bea6ace94f4128009e82b5a1d0a776f9f0abea6b52df48b7b7019cee61dcd160e63955e0d5f866d8872339154ee17cb9dd7d091562d76b6377e3409914ed8911fd856dc04346083d6b1af02ff07406b474f7dd6cbed51230a85c1e940a4cd21eb50622eee29a4e45231a6e6900134c63cd04f34c27340084e0fd6a263d4539db8f7a89db3cd318d634c63cd0e79a8c9f5a621ae7b542c69ec6a2634d0c6b526dca37d0d2f5a76dfdd37d2a901968bb9c01eb5d658c1e4daa2639c735cee9b17997b18edbb9aeb40ad1098cc1a5c53e90f34c430f4a8d14024d48f802a1ddb7ad005a53c5395bd6a924c776074ab6a770a604a28a6ad3a800c514514804ef484d0d49400134a280294503109a4a5ef450025656b568658b728c915ab48ca19482383401c3302a7069b5b5aae985099231c56332953835250da2968a004a29692800a28a2800a5a28a0028a28a0028a28a007d14b494005252d1400d3494e2290d002668cd149400a0d598a1dc326a089773815a08b8502802bcb0aa213550d5bbb6c0c554a00514f14d5a7f6a004a28a2800a28a2800345145001451475a000f4a4a292800a0514a280168a051400b494506800a0525283400b4a4d25140094b8a4a5a00d0d1909ba06bac418515cc684b99c9ae9d7a0a86691d87d140a2a4a0a4a5a6d300a0d2668340099a28a4a008a6055838edd69f9c8cd2919151a82a48ed4008eb9e7bd0a7239eb4e3cd309f4a00522a26a97ad46f40c8cd369e69a68018d4c269e4d4740094c3d6a43d2a36a0634d3694d36908434d3d294d2134c4329294d25020a28c52e29800a51480734ec52185253a8c5000297140e945001498a5a2800a281413408514b4d1484d0004d358f1485a98cf4086b1a81cd4a72dc28cd096524a7e63814ee4b65390e452c1b89c60e2b562d3901e467eb53fd950701714730ae5281f3fbb2783deaf2c48b0924fcddea84d1794f5346fbf193c8a699aa624d1ff10a845684b1808369c822a8c89b1beb4cd131b4bda9293348a1734b9a6e68cd0059864230335666941450179ace0d8ab56ee19949e83ad04345db49800633f515714f159324999b318e074ad0b797cc8c1a868c248b07e61c567ca3cbb827d79abca78aa97a0ef46f7c511dc51dc8e6904fc818e2a92fc9203e957b2a2218ebd2a84bc486b43a226fcbab4c228d228f25947cc6a9eaf34eb247e63904a02467a1ab3a3ea3025bf97390190f048ed59fab5d0bcbc2d183b40c0a63451772e727ad4d6a7b5364b7748964652158e05321243d2065bb98824640ee3352e95266365f4350b2b15dc791d2934d7c4eca7b8a996c653d8d91d2909e29aadc505b22b330026984f14b9a613c520119b9a6b1ef484d319b22980d27939a8d9bb52b1a889a0009cd46c78a713dea2634c635cd3295a931cd30155726a565fdd30f63491ad4bb770c7ad52022d0adcef6948e074add0d55ed2110401454c2b544928141a4534ecd302323351b4408ab1462802a0b7c0e2a48c32d4f8a4c50028a78e94d5a75001494b4868011b914d5a750b48051452d2500277a281d696801290d3f14d2b40c8a550ebb48e2b1efb490e0bc639f4ad97a3191401c5cb6ef11c30351575d776892c67e519ae5eea130ca548a92886929692800a28a2800a5a4a5a0028a28a0028a28a0092928a2800a28a2800a434506801a6929d46334012db292d9abddaa1b74dab9a9a8028dd1cbe2a0a9673990d462801cb4ea6d2f4a0028a28a0028a28a002834519e68012968cf3494001a4a292800a70a68a70a005a5a28a004a4a5a4a002945252f6a005a2933466800a5a4a28036f405f9c935d0a9c5606820804d6f2d43355b12034669a29d4861486969280128a5a4a002928a4cd0021a8d8d48d4c34006722987ad2d21340076a6352e690f340c6114d34f6a8ce6801a6a3352115191400d34d34e348680184534e29c4d30d0021a61a71a69a04368a5a4c53100a5a41466801c052d3452e680169d9a61a5078a005c51499a42d8a4171d46699bbde98d262815c977629378a84be690066a057256714cde4f4a72405864d588edc05e94ae2e62b0477edc54b1dae7ad5a8e202a45503a52b937218e15538c54ca9cd2f7a70a4200a01a5206451de83480ab790ef4c8eb59c0b47256cb8c8acfbd88a90c071deae2cb8be83e32d215c1f94d24f16de0d4104854e33f4ab50a3cc4eeed5a1b26513c1a4a9a78f0491daa11c522ae149466933405c5cd3e37dafed5151408d08dd36926a5b1980976e7863fad5189b2b8353bed8f6153f37f5a4d19c91b00e3806abea0dfb953fdda2da5f350377a2ec6e81c7b54f5335a3208e3deacf9f7aab70b86cd4b11770aaa7b536e978fa559bc4b3a4d925e97566c32f22b6a2b0b4b55cb8524776ae6ec6f1ed1d993a918a496e27b96cbb337b6698cd6d66eeda7b5091302c8dd05612361855c834e9a65662a400a4e6a8b70d40178ca7cb0b8e2a18898ef01e9cd490c8ab192c33c541237ef15a93259b6adcd2e706a28df31ab7b5296ac8e71ccd5193cd231a6b3714840cd835131e6958f14c278cd301ac6984f38a5634d63c5301a4f6a8cfa538d34f34c637bd3d17342ae454aa3005000a3005381e453738a456f9853406aa1f947d29f4c8f941f4a7d6c48e534ea8c1c1a7e73400e539a753052834c070a2901a5a00514b4dcd2d002d2119a5a2801bd2814a681d2900a0d21a4ef4134000a70a6034ea005cd04d26693340c6bf269295bad250036b2356b1f314c8a39ad8a6b286183401c532953834dadbd56c304bc62b1594a9c115250da28a2800a5a4a5a0028a28a0028a28a007d1452500145145001494525002d4b047b9b351a2ee6c55d8942ad004806062918fca68a6c9c29a00a321cb9a41437de340a00514b45140051451400514514005252d2500141a290d00149451400a29c29052d002d149450006928a4a002973c525213400ecd2669b45003c53ba5460d3c1e4500745a10fdce4d6d0e9593a2afee056b0a866a851d69d4da5a4314d25069334005069734dcd0006928cd19a0069a69a7535ba50034d30f14e34d6a004a0d25213480434d22949a693c50310d46e69c4d34d310c3cd309c53cd4668011a9869c4d309a004cd2668269334c429a693485a985e815c7e68cd445c534cb40ae4fbb1417aac65a699680b96bcca6992abee26942331a0572532d27999a120279a9a3839e94ae2b90fcc7a53c424e335696200d49b40a5715c816df02a748405e45389c529618a42b8aaa02d396a3cf1406a404a0d2034c0734a0f3480901e6973cf15183cd2e7e6a00909e4506985b914e27340871e9515c20688834fe7d694fcc9d298cc475292e3d2ad4370554edeb8e6a5bab7dc9bc0e455042524ad13358bb97363345bc8e0d539060d5c33feec20e87a5432c44af4aa2ee55cd2d274341a062d21a4a09e2810a8e430ab518123024f1544d4d13f18a04cd2b2976c8573c1e957df053ea2b2230230af9e735a6920922c8f4a868cd94617313b63f84d12b175248c5070b72e0f719a9272857e5aa4691655b72be7a6f1919e6ba84b4b2b45dedb7d72c6b922db5b3e9525c5dc93be598f4c629967453eb36ea7ca8816ddc64702b99b81b66607b1a92d50c93a81eb4ba91537b26c20ae7a8a0075b90d80dd2997407f0f40699064f14fb84da847e3412cbd6726f8141ec2ac6ee3159da7c9f2e2ae96e73593307b8b9a6e79c5213de9ac7bd21013ce2a3271431a69a00426984d38f2298698087ad00734a0669eabc500083069dda8f4a6b1eb4c0463427dea613cd393ef0a680d6847eed7e952d456ffea96a5ad91218a5a2968000696929714c0514b4da5a00775a3a5029714000a28a2800a414b494800d252d34d0028a285e9450004d19a290d00358f34bda986941e2818a281499a51400c740c30c3358fa96999cbc62b68d35c6e520d00714ea51883da9b5a3aa5b18a52d8e0d67d494252d251400b4514500145145003a8a28a002928a280128a29f12ee714012c11e393560522ae0629d8a04148e7e434ec5324fba681944f2c694521eb4a280168a28a002929692800a28a2800a28a2800a4a290d00140a29450028a5a414b4005251450019a4a28a0043494a692801296942d2500585680da9041f3b3c1ed8a8d3ef0a8c5491fdf1401d5e93c5bad6975aced338b7157d4d666a3a971499a33400628a33c5266818134da09a42680173499a29b9a402e6909e2909c5349a0043d690d19a696e680169869775318f140085b14c639a1985465bde980a4d34b531a4c546d28f5a057252d51b3735134c3150b4f4c572c16a89dc5576b8f7a89a526815cb065a699fdeabe58d204634c572633546d2e6810934f583b62815c8b7934618d5b16f8ed52ac2a052b88a490b354c9073569554528c034ae0442002a658c01484f34a5f8a403d40029548ed5183c500d211286e6909f985301e68279a00918e40a09e39a613416e2900fcf1429a6678a5071400f069c0d463a75a7213bbda810e0d86a711c839a6e09a7aa127148055e3de9e471c53b660f229fb40fa5003553e5e69e8a3183406c0c51ba801190631dab1af2128fb87435b39aab75179919e39aa4ec545d999b6f264ed6fc2accf2f9980a3a5526528f56a0917866fc6b4354559570738a8eae4c15d8ede954d9482699421a4a0d25020a556da69290d022d213260035a163275435970b9038ab16ecc92063de9325966e462653f8505008430eb4b79ca2b0a8d159867b508712a49c39a6e2a49fef56968f690dd2bf9b9f979e299a5ccf863909c203934fbcb392d911a4182c335d1b4f6562981b411e8326b1357d452f5542291b4d315ccf85b0d5349b8ae4f4c5564386153b49950a29122d8be2422b473915936c76dc56aaf4ace4652dc5ed4c2734e34c3d6a44309a6d2b75a4a602537bd38d2eda004039a7a8c13463a52f7a00427e5a8d8f3f852b1e0d479c9140053e3fbc29952275aa406b5bffaa5a9b150dbff00aa15356a890c521c8a158374a7e29808294518a0530022802968a00514a2928e9400ea4a4cd2d0018a4a5a4a4014869683d2801a2968a4a00290d2d06801a69283487a500276a169a334e53c5031d41a0521a00ab7f6cb3c046391d2b969e3314854d7658c8ac7d56c7765d4734868c0a29cca54e0d3690c2969296800a28a2801f494b494009494b4940055ab74c0c9a8225dcd57506050028a5a28a042d46ff74d3ea395b0b40ca6df78d028ea694500145145001494b4940052d251400514514009494b49400528a4a51400a2968145002514525001494b49400514a0668228014038a61a76e20629b4000eb5320fde2d46839a953990629303a8d38fee40abaa6b36c999230369ab7e691d6b36cd2e59079a7554f3b14a6e052b85cb39141aabe7827ad2f9e29dc2e4f486ab9b8a0dc7145c2e4f9e29a5aab99fd2a233b67a1a2e172d33530c9559a573d05465e43da8b873169a5a69941ef551bcc27da90a39e8695c5cc586980ef513dc8f5a87ca73d49a436df5a7717303dc8f5a88dc9a97ecf91d2816e01e945c5cc563331e829ac5dba55c684014a230074a2e17281476a4f24f7abc1066860051715ca62db3da9cb6f5681c0a6e69dc08bc9029c230074a563cd216e28015540a0119a6eee2999e6802566a0b7151e79a33401203499a6eee29035201f9e697351eee690bd004d9c0a030c545bf8a031a044cac3349bf9a60e99cd03ad201e58d3b76475a67269eb193400aa7a53c64d3922e2a6488019a404491926a558f069ca36b5389e734842ed1c7ad2ae179a6f5a5ed400f2dc5283c5301e2941e280169075a33c520eb400b4879a3f8a83d73401997f0ed9370ef54d1886c7635b17481e33eb58f28dae45691669165e8c2884e7191552618e94e8db7a633c8a9658d5541eb91565944d252b0c1a6d0019a434521a04391b69ab2242c001daa9d4f0bed1408d2cf9b68477150a4c5571ea292d1faa9ef446551c86ec6902239fb1a209e489584648dc307144ec181229fa69537918906549c1a65dc62c734ac000cc6ad36992476924b28c606715b46e2ced30a9b777a0acad43586955e20a029e2981900fcd538204673d6aa8383562301873489230c5661f5ad8539506b1a5fbd5a76edba21f4a8910c958d34d29e45345492230c8a6d3c50073400d519a701c5281cd1dcd001fc34c73d2973f29a8dcfca2801a4f269bda94f5a41d4d301ddea48fa8a8c738a9621c8a680d587fd52d4807151c6088c62a45e056a89214ca4b8ec6acd46ea0f3dc53a370c314c07528a0d253014d20a5a050028345252d001474a3345200cd266969b8e6801d49451400bda90d3a90d00368a0d213400d3487a52d21e9400ded4aa38a4c1c50322801f48690134d2dcd031c29ae81d70c29c3a51401ccead008a63b4706b3eb7f5a877a6e03a5605494252d149400b45145003a8a4cd140052514f8d0bb5004d6e9deac5222ed18a5a042d14514009505c1c0c54f55276cb5032214ea68a70a0028a292800a28a2800a28a2800a4a5a4a004a28a280014e148296800a3345140094514940052d2528a00514514b400d229314e3494000ab9a7c7bee17238aa82b4f474ccc0d4bd80e8e18c2a6714fd81bb52afdca17ad642b8c28bd00149e528ea29ff00c54afdbe9482e44215ce7148635ec2a6cfcb4cef405c8cc6076a4f2bbd48793484f1405c88c793d2828318a901a6e79a02e304400e690a0269ec6984d021a5474a6ed029c69a4f1400854669ad8c519a6b1a6014d268278a6679a062934d278a696e69ac78a600185359b9a666909cd301e5b8a66690b5319e980ece4d358d47be90bd3b0c97753775445e8ddc714012eea0b545cd1d7ad0049ba93753694671c0a005079a5c8a021269e2139a4210139a72826a648454c90803a8a40578e366352ac3822a54f90f14a4e4d200f2d7ad38003a5369d4843c367ad28351834a0f3480933f3519e45479e6949e280242dc505b34ccd00d003c1a50698a69ca793400ea33cd277a0918a00534869334039a00461906b3af62c7cc05688271cd452a6e422a93b0d3b1908c63606acc60cad8cf1daab4c851c834f86420607515a1a5c4b84c1fa557ab6c8cebb8f4aaae30714c6349a4cd04d266810669e869940383408b91c9875c54ac0349f5e6aaa3002a50c5b1400f9d42f0b50c2db6553ef52329d993deab13f35328e920d3a351f6891f70c6e02b9eb96df3b11d33576396ee68842a58a55ab7d189c3cc703d280312a58f246052de208ee1d57a038a64648e948412f1815a1627308acf932464d5cd389db8a9912cb940eb4bde83d6a09131cd18e694f514878a003a1a4279a463c8a693f3500349c66999e29c7ef533bd0021e94a3ad201c5380e94c0728e95344bf30a89462acc23e61548468a0f907d29d8a45fba296b5106da6aa6d391525250026ea5cd18cd285a6014a050148a75002518a7521a0069a0507ad14805a28a2800a4a052d002d34d3a9a6980d3494b452012929d8a434009da92973c51d45002535853f18a69a0603a514514010dcc425898572b75118a52a4575e45646a965bd4b8eb498d183494e652a7069290c4a2968a0028a28a00551938ab90c7b464d476f18ea6ac8e94005252d1400945148680118e066a939cb5599ce16aad002d2d20a514001a4a28a0028a4a5a0028a28a004a0d149400514502801452d145001494b494005251450014a29296801696928340051494b4000ad9d157906b1eb7f4542b0e48eb512d84cd91f7694547bb8c5286e2b210bde95cf34cddcd05b3cd003c9f96a31d682dc5377520149e6909a6eea466a602e714dcd34bf14cf339a00909a6938a63495197a0090b7348cc315097e69ad2530242d4c66e6a32e6a36624f1401333f151992a325aa32d4c64864a633d47f8d373cd301e5e985f9a09c76a6ed27914c019c9a696269db18d2f92698c8a8a9c407bd3d201de8115bf0a508d56fc914e0aa3ad00545889a7880e6acfc8bd29378cf1480608054a912818a432e45206ef4012045069e081daa0dfcd1be901396e2856a84b1a40d4809f70a42fcd459e6968025df4a1ce2a3a55e94807a9eb4e1d698bd69ddc5021d9c629c7a531ba538722900e1d28a414a2801c31467069b9e78a5ed400ece79a5a6e38a51d2801690520eb4ea00434d6eb4ea434c0a17f17cbb85505386cd6cca81e320d644cbb5b157165a64de612a14541329ef4e81f079ed4e95bcc39ab28a86929cc3069b4c41494514089636e05481f9aae8706a5246063ad004fbcb2e2a03c3d4c1805c77a81cfcd40cddb7d421b7b28f2019318aa573ab4d31c03b47a0aad15bcb326e4195141448feff27d28190cacccdb9ba9a588d13b891b20629b19e68112487767d2ac69edc9155e4c638a96c0fcc6a5ec26699e314134d3c8a09e2b324563c5358f1413c5349e28006a6b507a5213f2d0035bad2639a71e68c7229808075a701c0a07534aa38a00728ab56ebf30a81455cb65aa888b42969053ab51051452d30014f5a68a5c62801f4b51eea7839a0008a4a534500467ad00f38a5ef49b70734805a4345349a005078a5ef4d14a2980ecd251494005253a92801290d3a9a471400c34e038a4229c3a5200c5348e29f4d6e9400dc7140a776a40281894d740ea4114fa31401cfea3a71525d071592ca54e0d76722075208ae7b53b2f2db7a8e290ccca28a290c29d18cb536a6b7196a00b0a3038a7034514085a292968012969052d032bdc9aaf535c1cb542280169692968010d252d250014b494b400514514009494b49400528a4a51400b451450025252d25001451450028a5a414a2800a0d141a004a5a4a5a007c4bbe455f7aeaacd36c2800ed5ccd902675c0ef5d5c4088c0f6ace4263da94702931c503deb3244c77a4249e0538fb5000a008c9c0a314a4518a008fbd31cf3536d03a534c7939a00848e334c1eb5391918a464005032067e718a8db8e48ab02319cd23203d69815ff000a61c93568aa8a6954038a00aadb80a6ec26ad10b9e698e5470298158ab6690c46a72ebe94d69076a6321f26811014f32d30c94c05f2852ec502a3321f5a6972698128da0d297155f75216340cb1e68f4a679bcd439a4cd004e65f7a697a8a8cd0049bb34679a8c53a810f2680d4da05003f7734b9a677a75201f9e2814d069475a40381e453ea3cd3c5201e3a52834d534a3ad00394e0d3cf351f7a7f6a403fa8a518c53474cd00f340870a33cd277a09e9400b9c53fb533b5394e40a403d7a668148a68ef400b8e683d69334a4f1400507a1a33494c06f5acfbb8b9cd685413264114d0d191cabd5805761f5a8655dac734210700d6a58d9454356a503b5563d69884a2928a0051d6a45c75a8a9ea72280274c11cd46fd695413c0a47a00d3d1eee3883472f01bbd5abdd316653240464d61c485cfcbdaafdb6a0d6abb4b6ef6a0667cd13c2e55c60d09d6a4bbb86b890b30a890f348095d702a4b13f31a8981c64d4963feb0fd293133481f96933c5203f2d2039159922e69281d2947228013b534f4a51476a006e38a5f4a3b53b1c0a0400734e55a00e6a451c0a602a8abb6e3e5aa9d066a7d3e4f32327deae205ac52d14a7a5682014ec54609cd480e4530140a7520a5a006b2d0bc0a7521a0033485b14535b91400a0834b4d41c52d002d308a7d35a801b4aa79a31428e6801f4628a2800c5252e6909e28010d34d2e69b9a005a0534f4a703400535a9f4c6a005a4a5a290c4a28a434001e9556ee112c44559a69a00e4ee61314841a2b6751b30ea5875a290ce7ead40b8150c69939ab4a30290c7525145020a5148294500380a462054724a17a75aaef2963d6818929cbd36933934b400514514005252d1400514514005252d25001494514000a7520a5a0028a29280034945140051451400b4a29296800a434b4940052d252d202ee9885a6071c574cbf74561e92aaab96201ada12a63861f9d652dc964a0f1499e29bbd48ea280c0f7a901d9a693834679a4638340031a4cf148dd29bda80177d34b9cd37b9a63f5a00733530c9c5349a4c5003bcca63494d34d6a6038be4530be3bd349e2984d318a64a617a4269a69801639a693477a434c0426909a0d34d31813499a28a0028a28a602514b4940052d252d0002969296801694520e94a3ad20169690d3874a00169d8e69abc1a766900b8e29cb494e148400d3b3cd3475a5a4049da9453474a703c50028e94b9e69aa6973cd201d9e694d309a5ed40878a50714c56e2973400e53c9a713c8a8c1e6958f4a007134678a693914aa78a005078a05203484fcd400a7ad46fd734e269afd298142f139ce2a98386ad2b81bd0d6630c1ad1148980ca135038e69ea4918a245c0a6321a28a4a6216954d2503ad004c84819a47342114b21047140c62b95e94f452e6a350598015a5159488a0803268194e5da1428ea3ad46bd6a7b8b768c966e99a85719a404849229f647f7a6984fcb4fb3ff005b49899a0bc52a8a4514a3826b32400a41de941e68a0041de90528eb4a06280100f969c074a147cb4e039140814726a403a5228a78c63ad302bdecbe4db9f53c559d1f8b407d6b1b54b8f32508a785ad8d19c1b31922b4881a20d19a6ee5f51f9d2e47a8ab10bde9e38a8f9cd3c5003b34669b4b4c05cd145140094869d48450002969292900ec5371cd19a51d68016900a53494c028a28a004a434b486900d349de9d8e29b8e68014d1451400521eb4ea691cd301452d2519a000d34d2961eb4d245218525191eb4647ad0031d030c1a29c48f5a2819fffd9);

-- --------------------------------------------------------

--
-- Table structure for table `tbl_eyebrows`
--

DROP TABLE IF EXISTS `tbl_eyebrows`;
CREATE TABLE IF NOT EXISTS `tbl_eyebrows` (
  `face_id` int NOT NULL AUTO_INCREMENT,
  `employee_id` int NOT NULL,
  `eyebrows` blob NOT NULL,
  PRIMARY KEY (`face_id`),
  KEY `employee_id` (`employee_id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `tbl_eyebrows`
--

INSERT INTO `tbl_eyebrows` (`face_id`, `employee_id`, `eyebrows`) VALUES
(3, 45, 0xffd8ffe000104a46494600010101006000600000ffe102ec4578696600004d4d002a000000080004013b00020000000b0000014a8769000400000001000001569c9d000100000016000002ceea1c00070000010c0000003e000000001cea00000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004d41524b204c4f554953000000059003000200000014000002a49004000200000014000002b8929100020000000332340000929200020000000332340000ea1c00070000010c00000198000000001cea0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000323032343a30313a32342032303a33393a343800323032343a30313a32342032303a33393a34380000004d00410052004b0020004c004f005500490053000000ffe1041d687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f003c3f787061636b657420626567696e3d27efbbbf272069643d2757354d304d7043656869487a7265537a4e54637a6b633964273f3e0d0a3c783a786d706d65746120786d6c6e733a783d2261646f62653a6e733a6d6574612f223e3c7264663a52444620786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f222f3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a786d703d22687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f223e3c786d703a437265617465446174653e323032342d30312d32345432303a33393a34382e3233373c2f786d703a437265617465446174653e3c2f7264663a4465736372697074696f6e3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f223e3c64633a63726561746f723e3c7264663a53657120786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a6c693e4d41524b204c4f5549533c2f7264663a6c693e3c2f7264663a5365713e0d0a0909093c2f64633a63726561746f723e3c2f7264663a4465736372697074696f6e3e3c2f7264663a5244463e3c2f783a786d706d6574613e0d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c3f787061636b657420656e643d2777273f3effdb00430007050506050407060506080707080a110b0a09090a150f100c1118151a19181518171b1e27211b1d251d1718222e222528292b2c2b1a202f332f2a32272a2b2affdb0043010708080a090a140b0b142a1c181c2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2affc0001108002100b503012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00c8fec44b38b2c01c0e71eb4db58951b7ca00005747771a6c259b03b9ae5b519c16658146de318edea6bcaa4dcf73e82a25109e68d8e31f8fb557b544918b92148eb9ee2b32e2619f94966031d7ad5417d244d8320c1eb8aea50399ccedec022ae304f35b5015c0c579d2788da340178c77cd5bb7f1632b8dc4e48e06718a974d846a25b9e891ca3762ac2c9dbb570d078c22dc15d307b90735ad69e248a63801b27b0ef59b8491aaa917b1d307f7a72b1cf35996f7ab36d64e549c55e12fcdb477a82cb3b854f0cfb475aa829dda90cb8d75818079aad24a58e7b546071cd4535c2c2a49ec3bd022466f535134c02fd2b12fb5d58579ef5ce5ef8aa47561136d15a2a6d9129a89d95c5f4317f1827d01ac7bcd62d8290cf8f622b84b9d5eeae49d85c8ee6a8b1bb95babe3ad6d1a5639a559b3b93ad5b8002b027b1a45d6519b12607a63bd70999d1b19c8fad5bb7b8907deff001aae4447b491e816cf1ce539c86ea2a8eabe1a17521684019e847f5acad32f9d0aa839527a8eaa7fc2bb6d3275b98b6c870c38208eb5849b83ba368be6566799dc6873c32f9720da47b75a2bd1f50d2e3b8b8de13da8a1621f527d922a6b1be56114676a8fbc7d6b93d4108728159b8e029e9f535dccd68f264ff09acc9b4cdc4fcbb893dc573d29a8a3ba74dc99c3b595e4c988a2239cf2473511f0edfb9dd206ebd057a0c562abc140bec0715723b64038515d2ab183a07990d0ee06728411d986334a9a5b6cfde2107bfb57a69b48db259727deaabe991f276e4d57b633744e03fb2e68f1b53729e98ea2b4f4fb39e16032dcf383debaa1651f1941f953bec5186dc106450eaa635499069ece1c64e06ece3f9d6d5bc87ccddd6a8476fb570bc66af409b140ac5ee6e9591a41f2b4670bc1cd408c4fbd3ce48a918924e56b2efae3381d7357e5c9ed549e00c79a682c735a85acb792ec505d7afa0354dfc38c7a0273d78ef5d7ac210f14e11827dab4551a3274ee72b0f8713ee91c9eb5a90e8116cc3a8200e95b4910f4e7d6a609da87524c4a944c21e1cb52c4f96a07a62a5fec4b68e32b1a20cf5f96b642734f2a08c74a9e763f67139997408836e5e0fb0abda44135ac8048db81e3deb5bc904f73f8d4e90853f778fad6729b7a028a5b138440a3231c71453d02aa8c671db34567a14671ff005755dbefd1456513ac89bef1a72d1456c8cd922d2377a28ad0c884f534a3ad145034397b54e9d28a2819661fbf529e94514010c9559a8a280233d68ed45140872d4eb4514fa12b71e3ad29a28a9e836489d054a7afe145159b10a3ee8a28a2901fffd9),
(4, 45, 0xffd8ffe000104a46494600010101006000600000ffe102ec4578696600004d4d002a000000080004013b00020000000b0000014a8769000400000001000001569c9d000100000016000002ceea1c00070000010c0000003e000000001cea00000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004d41524b204c4f554953000000059003000200000014000002a49004000200000014000002b8929100020000000332340000929200020000000332340000ea1c00070000010c00000198000000001cea0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000323032343a30313a32342032303a33393a343800323032343a30313a32342032303a33393a34380000004d00410052004b0020004c004f005500490053000000ffe1041d687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f003c3f787061636b657420626567696e3d27efbbbf272069643d2757354d304d7043656869487a7265537a4e54637a6b633964273f3e0d0a3c783a786d706d65746120786d6c6e733a783d2261646f62653a6e733a6d6574612f223e3c7264663a52444620786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f222f3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a786d703d22687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f223e3c786d703a437265617465446174653e323032342d30312d32345432303a33393a34382e3233373c2f786d703a437265617465446174653e3c2f7264663a4465736372697074696f6e3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f223e3c64633a63726561746f723e3c7264663a53657120786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a6c693e4d41524b204c4f5549533c2f7264663a6c693e3c2f7264663a5365713e0d0a0909093c2f64633a63726561746f723e3c2f7264663a4465736372697074696f6e3e3c2f7264663a5244463e3c2f783a786d706d6574613e0d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c3f787061636b657420656e643d2777273f3effdb00430007050506050407060506080707080a110b0a09090a150f100c1118151a19181518171b1e27211b1d251d1718222e222528292b2c2b1a202f332f2a32272a2b2affdb0043010708080a090a140b0b142a1c181c2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2affc0001108002100b503012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00c8fec44b38b2c01c0e71eb4db58951b7ca00005747771a6c259b03b9ae5b519c16658146de318edea6bcaa4dcf73e82a25109e68d8e31f8fb557b544918b92148eb9ee2b32e2619f94966031d7ad5417d244d8320c1eb8aea50399ccedec022ae304f35b5015c0c579d2788da340178c77cd5bb7f1632b8dc4e48e06718a974d846a25b9e891ca3762ac2c9dbb570d078c22dc15d307b90735ad69e248a63801b27b0ef59b8491aaa917b1d307f7a72b1cf35996f7ab36d64e549c55e12fcdb477a82cb3b854f0cfb475aa829dda90cb8d75818079aad24a58e7b546071cd4535c2c2a49ec3bd022466f535134c02fd2b12fb5d58579ef5ce5ef8aa47561136d15a2a6d9129a89d95c5f4317f1827d01ac7bcd62d8290cf8f622b84b9d5eeae49d85c8ee6a8b1bb95babe3ad6d1a5639a559b3b93ad5b8002b027b1a45d6519b12607a63bd70999d1b19c8fad5bb7b8907deff001aae4447b491e816cf1ce539c86ea2a8eabe1a17521684019e847f5acad32f9d0aa839527a8eaa7fc2bb6d3275b98b6c870c38208eb5849b83ba368be6566799dc6873c32f9720da47b75a2bd1f50d2e3b8b8de13da8a1621f527d922a6b1be56114676a8fbc7d6b93d4108728159b8e029e9f535dccd68f264ff09acc9b4cdc4fcbb893dc573d29a8a3ba74dc99c3b595e4c988a2239cf2473511f0edfb9dd206ebd057a0c562abc140bec0715723b64038515d2ab183a07990d0ee06728411d986334a9a5b6cfde2107bfb57a69b48db259727deaabe991f276e4d57b633744e03fb2e68f1b53729e98ea2b4f4fb39e16032dcf383debaa1651f1941f953bec5186dc106450eaa635499069ece1c64e06ece3f9d6d5bc87ccddd6a8476fb570bc66af409b140ac5ee6e9591a41f2b4670bc1cd408c4fbd3ce48a918924e56b2efae3381d7357e5c9ed549e00c79a682c735a85acb792ec505d7afa0354dfc38c7a0273d78ef5d7ac210f14e11827dab4551a3274ee72b0f8713ee91c9eb5a90e8116cc3a8200e95b4910f4e7d6a609da87524c4a944c21e1cb52c4f96a07a62a5fec4b68e32b1a20cf5f96b642734f2a08c74a9e763f67139997408836e5e0fb0abda44135ac8048db81e3deb5bc904f73f8d4e90853f778fad6729b7a028a5b138440a3231c71453d02aa8c671db34567a14671ff005755dbefd1456513ac89bef1a72d1456c8cd922d2377a28ad0c884f534a3ad145034397b54e9d28a2819661fbf529e94514010c9559a8a280233d68ed45140872d4eb4514fa12b71e3ad29a28a9e836489d054a7afe145159b10a3ee8a28a2901fffd9),
(5, 46, 0xffd8ffe000104a46494600010101006000600000ffe102ec4578696600004d4d002a000000080004013b00020000000b0000014a8769000400000001000001569c9d000100000016000002ceea1c00070000010c0000003e000000001cea00000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004d41524b204c4f554953000000059003000200000014000002a49004000200000014000002b8929100020000000330310000929200020000000330310000ea1c00070000010c00000198000000001cea0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000323032343a30313a32352031333a30383a323700323032343a30313a32352031333a30383a32370000004d00410052004b0020004c004f005500490053000000ffe1041d687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f003c3f787061636b657420626567696e3d27efbbbf272069643d2757354d304d7043656869487a7265537a4e54637a6b633964273f3e0d0a3c783a786d706d65746120786d6c6e733a783d2261646f62653a6e733a6d6574612f223e3c7264663a52444620786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f222f3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a786d703d22687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f223e3c786d703a437265617465446174653e323032342d30312d32355431333a30383a32372e3031343c2f786d703a437265617465446174653e3c2f7264663a4465736372697074696f6e3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f223e3c64633a63726561746f723e3c7264663a53657120786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a6c693e4d41524b204c4f5549533c2f7264663a6c693e3c2f7264663a5365713e0d0a0909093c2f64633a63726561746f723e3c2f7264663a4465736372697074696f6e3e3c2f7264663a5244463e3c2f783a786d706d6574613e0d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c3f787061636b657420656e643d2777273f3effdb00430007050506050407060506080707080a110b0a09090a150f100c1118151a19181518171b1e27211b1d251d1718222e222528292b2c2b1a202f332f2a32272a2b2affdb0043010708080a090a140b0b142a1c181c2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2affc00011080017006e03012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00cef8696be46931c8eb8ddcd7637de2ad1b4c3b27bb8f78eaa39c5734f05c699e1d8adec86d72a101c735cc4be11d4efdbcc9db39e99ed58c7952d4e97cd7b23bcff84eb4491b8ba503deadc1aee9f78336f751b7b06af2f6f03ea30e0aed61e99aa3368ba9d8bef48de3f75349b8969491ecc2ea361c303f4a7ef07a5793e99aeea56c555999f9c10d5e87a65f1b9b5477e090295d1ad8d7cd217038aaed360554b8b9dbc834b72d2d0bed20271481d73835c95e78945b3300092b5cf5df8fee8b15823fc69a444a563d35dd0f702abca148e31cf4af2897c69ac3658b003b7151c7e31d61b19c91ec2aac999739ddeb96426b591719c8af0dd5a036fa8c919ecc6bd1edbc6376015ba87729eb915c678a4433ea02e20e15fa8f7a715664d47cd13e81b88d11c6e1c2f4acdbed62dec1732703d8514566cb463bf8e34fced2b263d42d353c43657dfead88c9e854d14536928dc4a4f9ac4be45bca436c19f502afd9b6de17a0ed45158f5378979998ae6a8cecc473451549b2cc3bad3a2b894b30e4f5a861f0dd986076ee27ae68a296ec868bcbe1fd3037ef215fcaada69160abf2c2800e3eed145525a117d4867d22cd9788d7f2ae33c4ba244366c000ddfd28a29a93b8a4935a9fffd9);

-- --------------------------------------------------------

--
-- Table structure for table `tbl_leyes`
--

DROP TABLE IF EXISTS `tbl_leyes`;
CREATE TABLE IF NOT EXISTS `tbl_leyes` (
  `face_id` int NOT NULL AUTO_INCREMENT,
  `employee_id` int NOT NULL,
  `leyes` blob NOT NULL,
  PRIMARY KEY (`face_id`),
  KEY `employee_id` (`employee_id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `tbl_leyes`
--

INSERT INTO `tbl_leyes` (`face_id`, `employee_id`, `leyes`) VALUES
(3, 45, 0xffd8ffe000104a46494600010101006000600000ffe102ec4578696600004d4d002a000000080004013b00020000000b0000014a8769000400000001000001569c9d000100000016000002ceea1c00070000010c0000003e000000001cea00000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004d41524b204c4f554953000000059003000200000014000002a49004000200000014000002b8929100020000000335390000929200020000000335390000ea1c00070000010c00000198000000001cea0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000323032343a30313a32342032303a34303a323700323032343a30313a32342032303a34303a32370000004d00410052004b0020004c004f005500490053000000ffe1041d687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f003c3f787061636b657420626567696e3d27efbbbf272069643d2757354d304d7043656869487a7265537a4e54637a6b633964273f3e0d0a3c783a786d706d65746120786d6c6e733a783d2261646f62653a6e733a6d6574612f223e3c7264663a52444620786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f222f3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a786d703d22687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f223e3c786d703a437265617465446174653e323032342d30312d32345432303a34303a32372e3539303c2f786d703a437265617465446174653e3c2f7264663a4465736372697074696f6e3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f223e3c64633a63726561746f723e3c7264663a53657120786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a6c693e4d41524b204c4f5549533c2f7264663a6c693e3c2f7264663a5365713e0d0a0909093c2f64633a63726561746f723e3c2f7264663a4465736372697074696f6e3e3c2f7264663a5244463e3c2f783a786d706d6574613e0d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c3f787061636b657420656e643d2777273f3effdb00430007050506050407060506080707080a110b0a09090a150f100c1118151a19181518171b1e27211b1d251d1718222e222528292b2c2b1a202f332f2a32272a2b2affdb0043010708080a090a140b0b142a1c181c2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2affc00011080022003a03012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00d2912abc9c1eb8ab5330552338fad64dedddbc2b99e7507d335e14353ea2562c79e89d5a9e97284f1bc9ff0076b9d935f8c362cedda63eb8c0ac597c717ad215b6b75047af35d51a72672cea451de35c4678dd8ff7862903ab7a5700fe25d559bf7d02286008dc3ad6ae9daadd3c2259506cce1b69ce2add292466aac19d4e7de9db96ab41289a20cbc86e952703bd646e8a9a8adccfbf63f9683a571b77a5dcdc5d6373b2e7ef31e2bd366815d718fd2a9b5b22f1b062b2a53e5369c7991cae96a969232dda646ddab8fd4d72fa858496d7d31b52cc8ec4a6d5ce3dabd2a5b385f968f355c69f6eac484e4d75c6b58e3950b9e79041aa4c4048e561f747cb800575f656f2c3a5adb436cfb87de663d4d6c0b708b845c63d2a4489fa553aedf42561d2dd95748b7b8b48245b9c609ca8ce71568e335318caafad37cb3e95ccddd9d4a3646b9a8a4e94515cf1352ab53314515b99c800e6a64031d28a281206eb451454328fffd9),
(4, 45, 0xffd8ffe000104a46494600010101006000600000ffe102ec4578696600004d4d002a000000080004013b00020000000b0000014a8769000400000001000001569c9d000100000016000002ceea1c00070000010c0000003e000000001cea00000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004d41524b204c4f554953000000059003000200000014000002a49004000200000014000002b8929100020000000335390000929200020000000335390000ea1c00070000010c00000198000000001cea0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000323032343a30313a32342032303a34303a323700323032343a30313a32342032303a34303a32370000004d00410052004b0020004c004f005500490053000000ffe1041d687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f003c3f787061636b657420626567696e3d27efbbbf272069643d2757354d304d7043656869487a7265537a4e54637a6b633964273f3e0d0a3c783a786d706d65746120786d6c6e733a783d2261646f62653a6e733a6d6574612f223e3c7264663a52444620786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f222f3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a786d703d22687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f223e3c786d703a437265617465446174653e323032342d30312d32345432303a34303a32372e3539303c2f786d703a437265617465446174653e3c2f7264663a4465736372697074696f6e3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f223e3c64633a63726561746f723e3c7264663a53657120786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a6c693e4d41524b204c4f5549533c2f7264663a6c693e3c2f7264663a5365713e0d0a0909093c2f64633a63726561746f723e3c2f7264663a4465736372697074696f6e3e3c2f7264663a5244463e3c2f783a786d706d6574613e0d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c3f787061636b657420656e643d2777273f3effdb00430007050506050407060506080707080a110b0a09090a150f100c1118151a19181518171b1e27211b1d251d1718222e222528292b2c2b1a202f332f2a32272a2b2affdb0043010708080a090a140b0b142a1c181c2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2affc00011080022003a03012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00d2912abc9c1eb8ab5330552338fad64dedddbc2b99e7507d335e14353ea2562c79e89d5a9e97284f1bc9ff0076b9d935f8c362cedda63eb8c0ac597c717ad215b6b75047af35d51a72672cea451de35c4678dd8ff7862903ab7a5700fe25d559bf7d02286008dc3ad6ae9daadd3c2259506cce1b69ce2add292466aac19d4e7de9db96ab41289a20cbc86e952703bd646e8a9a8adccfbf63f9683a571b77a5dcdc5d6373b2e7ef31e2bd366815d718fd2a9b5b22f1b062b2a53e5369c7991cae96a969232dda646ddab8fd4d72fa858496d7d31b52cc8ec4a6d5ce3dabd2a5b385f968f355c69f6eac484e4d75c6b58e3950b9e79041aa4c4048e561f747cb800575f656f2c3a5adb436cfb87de663d4d6c0b708b845c63d2a4489fa553aedf42561d2dd95748b7b8b48245b9c609ca8ce71568e335318caafad37cb3e95ccddd9d4a3646b9a8a4e94515cf1352ab53314515b99c800e6a64031d28a281206eb451454328fffd9),
(5, 46, 0xffd8ffe000104a46494600010101006000600000ffe102ec4578696600004d4d002a000000080004013b00020000000b0000014a8769000400000001000001569c9d000100000016000002ceea1c00070000010c0000003e000000001cea00000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004d41524b204c4f554953000000059003000200000014000002a49004000200000014000002b8929100020000000337350000929200020000000337350000ea1c00070000010c00000198000000001cea0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000323032343a30313a32352031333a30383a343700323032343a30313a32352031333a30383a34370000004d00410052004b0020004c004f005500490053000000ffe1041d687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f003c3f787061636b657420626567696e3d27efbbbf272069643d2757354d304d7043656869487a7265537a4e54637a6b633964273f3e0d0a3c783a786d706d65746120786d6c6e733a783d2261646f62653a6e733a6d6574612f223e3c7264663a52444620786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f222f3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a786d703d22687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f223e3c786d703a437265617465446174653e323032342d30312d32355431333a30383a34372e3735343c2f786d703a437265617465446174653e3c2f7264663a4465736372697074696f6e3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f223e3c64633a63726561746f723e3c7264663a53657120786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a6c693e4d41524b204c4f5549533c2f7264663a6c693e3c2f7264663a5365713e0d0a0909093c2f64633a63726561746f723e3c2f7264663a4465736372697074696f6e3e3c2f7264663a5244463e3c2f783a786d706d6574613e0d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c3f787061636b657420656e643d2777273f3effdb00430007050506050407060506080707080a110b0a09090a150f100c1118151a19181518171b1e27211b1d251d1718222e222528292b2c2b1a202f332f2a32272a2b2affdb0043010708080a090a140b0b142a1c181c2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2affc00011080018002403012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f009eff005eb2d3ff00d74aabed5912f8ef4d43b5f701d8e319ae635cf0febf7d70cd141b14f5e79accbff0fc76fe1f282da55d4158162c09dc3be2b9e293dceb93696876ebe26d36f7ee4c064f422a6115acf875553e845793c7a7dd36aade5a4d1232fc980400d8aebf4abb9ec2ec5adcc9ba3276893b668943aa2a126f73b589c2c6029c01d28a64687673c1f4a2b13a2c745756c724af5ac8b9490121edf78ff768a29b6d129198f136efddd99ffbe29d16966ef22e6d502fd39a28aa4dd82c6ca5b2aa018e828a28accb3fffd9);

-- --------------------------------------------------------

--
-- Table structure for table `tbl_login`
--

DROP TABLE IF EXISTS `tbl_login`;
CREATE TABLE IF NOT EXISTS `tbl_login` (
  `admin_id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `password` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `picture` blob NOT NULL,
  PRIMARY KEY (`admin_id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `tbl_login`
--

INSERT INTO `tbl_login` (`admin_id`, `username`, `password`, `picture`) VALUES
(1, 'markme19', 'markmepogs', '');

-- --------------------------------------------------------

--
-- Table structure for table `tbl_mouth`
--

DROP TABLE IF EXISTS `tbl_mouth`;
CREATE TABLE IF NOT EXISTS `tbl_mouth` (
  `face_id` int NOT NULL AUTO_INCREMENT,
  `employee_id` int NOT NULL,
  `mouth` blob NOT NULL,
  PRIMARY KEY (`face_id`),
  KEY `employee_id` (`employee_id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `tbl_mouth`
--

INSERT INTO `tbl_mouth` (`face_id`, `employee_id`, `mouth`) VALUES
(3, 45, 0xffd8ffe000104a46494600010101006000600000ffe102ec4578696600004d4d002a000000080004013b00020000000b0000014a8769000400000001000001569c9d000100000016000002ceea1c00070000010c0000003e000000001cea00000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004d41524b204c4f554953000000059003000200000014000002a49004000200000014000002b8929100020000000333340000929200020000000333340000ea1c00070000010c00000198000000001cea0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000323032343a30313a32342032303a34313a313700323032343a30313a32342032303a34313a31370000004d00410052004b0020004c004f005500490053000000ffe1041d687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f003c3f787061636b657420626567696e3d27efbbbf272069643d2757354d304d7043656869487a7265537a4e54637a6b633964273f3e0d0a3c783a786d706d65746120786d6c6e733a783d2261646f62653a6e733a6d6574612f223e3c7264663a52444620786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f222f3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a786d703d22687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f223e3c786d703a437265617465446174653e323032342d30312d32345432303a34313a31372e3333373c2f786d703a437265617465446174653e3c2f7264663a4465736372697074696f6e3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f223e3c64633a63726561746f723e3c7264663a53657120786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a6c693e4d41524b204c4f5549533c2f7264663a6c693e3c2f7264663a5365713e0d0a0909093c2f64633a63726561746f723e3c2f7264663a4465736372697074696f6e3e3c2f7264663a5244463e3c2f783a786d706d6574613e0d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c3f787061636b657420656e643d2777273f3effdb00430007050506050407060506080707080a110b0a09090a150f100c1118151a19181518171b1e27211b1d251d1718222e222528292b2c2b1a202f332f2a32272a2b2affdb0043010708080a090a140b0b142a1c181c2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2affc00011080033007603012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00d96634cdd4d6619a8249f6d78a8fa9659ddbaa39240a2a9b5eeca864bd0cd8cf3ec2a91372db481b90718ed5598e49a146e1cf7a788f1d4d5a3377641e56fe4022950e1485edc5584641c669a610cdc38aa27948d036e1cf15309ca1c501628fef10d8a098dce4714c2c5a82727a9ab293022a9088327cad83511f3525c12c454b035c480af1d68dd8ac8370e83e60455a82e7cc3c1cfd7ad4b405f0d45314e68a8b94527e05675c3fe1cf5ad265041cd529a2dc8571f8d289bc91552332372463eb4f314101dcc726b2aea3d420726d9811fdd22aaadd5e1244f090df5ade291291bcd799e231c545e733375ef59a9f6b906522c7b934f36fa83e06e0b8e816b44915c85f2c40a049cf24f5c74aad0da5fece5f3f8529d3aea5604ca411d3da9872960939e294c87ef66a21a55c7189dbde9dfd90cdcc93313f5a2c27124176c8720f02acc3a9a30f9f1f53549f48503890e7eb555b476965ff0058c07b54b48ca48d79aee176014e7e86a6b64f981159d67a42db49b8027ea6b6615da0565226c5c5e05148a4628acc6552722a22334a1b1d29719acd33b65122308cf22a17b7439c8fd2aeeda8dc7a568991628345b3a004539268d480c315338354e4037722b68b0d0bc93c5b41079c6291ae177d65cb308d7a542da98561184cb7bd6a66e68db174334df3598fcb59d048f260918f6ad0b704e3229362e74c7ac7b9b9e6aca42076a1131532f159364318531ce293a53d8e4d2567715872b71452014522ec545a93bd145648ec6293f2d33b7e14515a2336308e2a07505ba51456d132915ee114f61543ca4fb431da339a28ad5183dcd281463a55e88018c51454c811383c519a28acd942f7a7f6a28acca42514514867ffd9),
(4, 45, 0xffd8ffe000104a46494600010101006000600000ffe102ec4578696600004d4d002a000000080004013b00020000000b0000014a8769000400000001000001569c9d000100000016000002ceea1c00070000010c0000003e000000001cea00000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004d41524b204c4f554953000000059003000200000014000002a49004000200000014000002b8929100020000000333340000929200020000000333340000ea1c00070000010c00000198000000001cea0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000323032343a30313a32342032303a34313a313700323032343a30313a32342032303a34313a31370000004d00410052004b0020004c004f005500490053000000ffe1041d687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f003c3f787061636b657420626567696e3d27efbbbf272069643d2757354d304d7043656869487a7265537a4e54637a6b633964273f3e0d0a3c783a786d706d65746120786d6c6e733a783d2261646f62653a6e733a6d6574612f223e3c7264663a52444620786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f222f3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a786d703d22687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f223e3c786d703a437265617465446174653e323032342d30312d32345432303a34313a31372e3333373c2f786d703a437265617465446174653e3c2f7264663a4465736372697074696f6e3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f223e3c64633a63726561746f723e3c7264663a53657120786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a6c693e4d41524b204c4f5549533c2f7264663a6c693e3c2f7264663a5365713e0d0a0909093c2f64633a63726561746f723e3c2f7264663a4465736372697074696f6e3e3c2f7264663a5244463e3c2f783a786d706d6574613e0d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c3f787061636b657420656e643d2777273f3effdb00430007050506050407060506080707080a110b0a09090a150f100c1118151a19181518171b1e27211b1d251d1718222e222528292b2c2b1a202f332f2a32272a2b2affdb0043010708080a090a140b0b142a1c181c2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2affc00011080033007603012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00d96634cdd4d6619a8249f6d78a8fa9659ddbaa39240a2a9b5eeca864bd0cd8cf3ec2a91372db481b90718ed5598e49a146e1cf7a788f1d4d5a3377641e56fe4022950e1485edc5584641c669a610cdc38aa27948d036e1cf15309ca1c501628fef10d8a098dce4714c2c5a82727a9ab293022a9088327cad83511f3525c12c454b035c480af1d68dd8ac8370e83e60455a82e7cc3c1cfd7ad4b405f0d45314e68a8b94527e05675c3fe1cf5ad265041cd529a2dc8571f8d289bc91552332372463eb4f314101dcc726b2aea3d420726d9811fdd22aaadd5e1244f090df5ade291291bcd799e231c545e733375ef59a9f6b906522c7b934f36fa83e06e0b8e816b44915c85f2c40a049cf24f5c74aad0da5fece5f3f8529d3aea5604ca411d3da9872960939e294c87ef66a21a55c7189dbde9dfd90cdcc93313f5a2c27124176c8720f02acc3a9a30f9f1f53549f48503890e7eb555b476965ff0058c07b54b48ca48d79aee176014e7e86a6b64f981159d67a42db49b8027ea6b6615da0565226c5c5e05148a4628acc6552722a22334a1b1d29719acd33b65122308cf22a17b7439c8fd2aeeda8dc7a568991628345b3a004539268d480c315338354e4037722b68b0d0bc93c5b41079c6291ae177d65cb308d7a542da98561184cb7bd6a66e68db174334df3598fcb59d048f260918f6ad0b704e3229362e74c7ac7b9b9e6aca42076a1131532f159364318531ce293a53d8e4d2567715872b71452014522ec545a93bd145648ec6293f2d33b7e14515a2336308e2a07505ba51456d132915ee114f61543ca4fb431da339a28ad5183dcd281463a55e88018c51454c811383c519a28acd942f7a7f6a28acca42514514867ffd9),
(5, 46, 0xffd8ffe000104a46494600010101006000600000ffe102ec4578696600004d4d002a000000080004013b00020000000b0000014a8769000400000001000001569c9d000100000016000002ceea1c00070000010c0000003e000000001cea00000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004d41524b204c4f554953000000059003000200000014000002a49004000200000014000002b8929100020000000337310000929200020000000337310000ea1c00070000010c00000198000000001cea0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000323032343a30313a32352031333a30393a333500323032343a30313a32352031333a30393a33350000004d00410052004b0020004c004f005500490053000000ffe1041d687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f003c3f787061636b657420626567696e3d27efbbbf272069643d2757354d304d7043656869487a7265537a4e54637a6b633964273f3e0d0a3c783a786d706d65746120786d6c6e733a783d2261646f62653a6e733a6d6574612f223e3c7264663a52444620786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f222f3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a786d703d22687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f223e3c786d703a437265617465446174653e323032342d30312d32355431333a30393a33352e3730373c2f786d703a437265617465446174653e3c2f7264663a4465736372697074696f6e3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f223e3c64633a63726561746f723e3c7264663a53657120786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a6c693e4d41524b204c4f5549533c2f7264663a6c693e3c2f7264663a5365713e0d0a0909093c2f64633a63726561746f723e3c2f7264663a4465736372697074696f6e3e3c2f7264663a5244463e3c2f783a786d706d6574613e0d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c3f787061636b657420656e643d2777273f3effdb00430007050506050407060506080707080a110b0a09090a150f100c1118151a19181518171b1e27211b1d251d1718222e222528292b2c2b1a202f332f2a32272a2b2affdb0043010708080a090a140b0b142a1c181c2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2affc00011080021004a03012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00a0f290e59ba6715b564e0a0c364e2b0f5385fec65533b83023f3acf1e27974fba586e6d25890f494ae54d7046373d73b892d92e136c89b81158f3e810dbcdf68b60d1bff00b2719a65bf8ac3463010fa60d595f11a49c3a2b7a8cd6bcac7c92339e5b94182a49ac8b8d066d6a726ec3b2e785278ae9ceaf64a0b791c9f4a8cf896007090803eb45a457b3914b4cf0a43a7a7cb85cf551deb6d21589768e82a83f89adc2f284567dcf8bad23ceff947a93472325c64b746adda2ba9c70474c567ef9c76ac84f1758df5c08a0977be7a2f3560de499e15aa1c6c46a6f4a164201a967d2e2bcb3d8caa481c6474a8107ce2b5ed8fc807b54c64d05edb1c75d69162098eea268cf678db6d545d02ce360f0de5cab7bb6eaeeeeeca0b95225519f5ae76eb4c7b762626c8f7aea84933b29548b7a995fd90a8bf36a3213f4150c9a35bc9d6fa53df8e2ad496d239e78fc6a316ae8dc67f1aa6d1d5cd1332e7478d78fb5cc57eb5497c3d15ec823c3c833c9639aea22d2da66fdf64afa56bdb59476e985403dea5cd58e6ab563b232b49f0fda69b0e2285431ea71cd698b74c54edb453723d2b9a6ee725ee0bfeb2b52dbee8a28a466b62697bfd2b36ebee1a28ad225c773265ea698bd47d68a2a8dcd383b54a7a1fa5145239dee40fd6928a2b319fffd9);

-- --------------------------------------------------------

--
-- Table structure for table `tbl_nose`
--

DROP TABLE IF EXISTS `tbl_nose`;
CREATE TABLE IF NOT EXISTS `tbl_nose` (
  `face_id` int NOT NULL AUTO_INCREMENT,
  `employee_id` int NOT NULL,
  `nose` mediumblob NOT NULL,
  PRIMARY KEY (`face_id`),
  KEY `employee_id` (`employee_id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `tbl_nose`
--

INSERT INTO `tbl_nose` (`face_id`, `employee_id`, `nose`) VALUES
(3, 45, 0xffd8ffe000104a46494600010101006000600000ffe102ec4578696600004d4d002a000000080004013b00020000000b0000014a8769000400000001000001569c9d000100000016000002ceea1c00070000010c0000003e000000001cea00000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004d41524b204c4f554953000000059003000200000014000002a49004000200000014000002b8929100020000000339390000929200020000000339390000ea1c00070000010c00000198000000001cea0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000323032343a30313a32342032303a34313a303200323032343a30313a32342032303a34313a30320000004d00410052004b0020004c004f005500490053000000ffe1041d687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f003c3f787061636b657420626567696e3d27efbbbf272069643d2757354d304d7043656869487a7265537a4e54637a6b633964273f3e0d0a3c783a786d706d65746120786d6c6e733a783d2261646f62653a6e733a6d6574612f223e3c7264663a52444620786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f222f3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a786d703d22687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f223e3c786d703a437265617465446174653e323032342d30312d32345432303a34313a30322e3938393c2f786d703a437265617465446174653e3c2f7264663a4465736372697074696f6e3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f223e3c64633a63726561746f723e3c7264663a53657120786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a6c693e4d41524b204c4f5549533c2f7264663a6c693e3c2f7264663a5365713e0d0a0909093c2f64633a63726561746f723e3c2f7264663a4465736372697074696f6e3e3c2f7264663a5244463e3c2f783a786d706d6574613e0d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c3f787061636b657420656e643d2777273f3effdb00430007050506050407060506080707080a110b0a09090a150f100c1118151a19181518171b1e27211b1d251d1718222e222528292b2c2b1a202f332f2a32272a2b2affdb0043010708080a090a140b0b142a1c181c2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2affc00011080053004d03012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00cad296e575024c4cb038e770e335b04fef38fa53951f6f26844cb64d795295ddcfa18c6cac5b8784ab6b55635c2d5a8519d805ea6a0bb130fbbc519ad08743b896dcc83a7a55596ce68972578f5a7622eae529feed5223e6abac39f5aaec9f350331ef74e926be69d5c00542807b54532dd36d5748dc28c039c56eb4595a81adf9e6b5536919ba7193bb266419e0522a7b5582940402b0674208d335ab63080ebc66a84237371dab66c63fde2e684296c7471c27ec3804eddbcd5068832956191ef5b90401ac3e5cf4aa26dd8123b56cf63922f538dd46ccc139c0c293c553d9c5759aa5979d6cd81c8ae6361562ac304549b2220b8a718c376a7914a2914446a366f98014aef806a3846f7cfbd41a9a1671e5ab7ad1551864d61c0de5d68457a8b8040fad084cef34d55fb201bd48ed50dd46a256c30ac2b5d52255c16c7d2a73aa463f881ad9caeac71aa328caf72dc90aba907a5729ae69bf6726e621f213c8f4addfed68ba12291e682ee228fb5d5874a9368a671b9ce29454ba8d91d36e76e7313f287d3daa11c8e291467ccd96c7ad5c8a3f2d01354252436e1ce2a75b81280437e1506c59790e78e94d594f3ce6b3352d464823296881e53fde3c0ac4d3f56d656e0fdba28a4889ea8b822a9444ced12e4d4df692475ac88eed5d030e01ed4e375c7d2aec41a2f31c72dfad5ab5bd789873c5717aadceab3b84b1616f17566032c7fc2a6d2af6f607115e3f98a47dea2c07697f7715e5994907cc395359319f9698d7485000dc9a9117e418a96229cb1ee523d6b2a582e2263e53b2fd2b649f5e950b81c9c54a3531824ccf99b25bd69edb881c631e9571f68e7155df38f96b4467262c470315333ec5e4e2aa2162467b1ab0f229ea3eb54473019188e066a26b39a6704b151e80d598991bb62ad2327140ee36cec0a302c4fe26b471b7806a3471d8d4959b02a374aa6ec7775ef451528d5ec47313511fbc28a2b4463d4251b718e39a30334514c4498c2714464f1cd1453045e563f2f3daa7dc7d68a2a181ffd9),
(4, 45, 0xffd8ffe000104a46494600010101006000600000ffe102ec4578696600004d4d002a000000080004013b00020000000b0000014a8769000400000001000001569c9d000100000016000002ceea1c00070000010c0000003e000000001cea00000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004d41524b204c4f554953000000059003000200000014000002a49004000200000014000002b8929100020000000339390000929200020000000339390000ea1c00070000010c00000198000000001cea0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000323032343a30313a32342032303a34313a303200323032343a30313a32342032303a34313a30320000004d00410052004b0020004c004f005500490053000000ffe1041d687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f003c3f787061636b657420626567696e3d27efbbbf272069643d2757354d304d7043656869487a7265537a4e54637a6b633964273f3e0d0a3c783a786d706d65746120786d6c6e733a783d2261646f62653a6e733a6d6574612f223e3c7264663a52444620786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f222f3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a786d703d22687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f223e3c786d703a437265617465446174653e323032342d30312d32345432303a34313a30322e3938393c2f786d703a437265617465446174653e3c2f7264663a4465736372697074696f6e3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f223e3c64633a63726561746f723e3c7264663a53657120786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a6c693e4d41524b204c4f5549533c2f7264663a6c693e3c2f7264663a5365713e0d0a0909093c2f64633a63726561746f723e3c2f7264663a4465736372697074696f6e3e3c2f7264663a5244463e3c2f783a786d706d6574613e0d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c3f787061636b657420656e643d2777273f3effdb00430007050506050407060506080707080a110b0a09090a150f100c1118151a19181518171b1e27211b1d251d1718222e222528292b2c2b1a202f332f2a32272a2b2affdb0043010708080a090a140b0b142a1c181c2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2affc00011080053004d03012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00cad296e575024c4cb038e770e335b04fef38fa53951f6f26844cb64d795295ddcfa18c6cac5b8784ab6b55635c2d5a8519d805ea6a0bb130fbbc519ad08743b896dcc83a7a55596ce68972578f5a7622eae529feed5223e6abac39f5aaec9f350331ef74e926be69d5c00542807b54532dd36d5748dc28c039c56eb4595a81adf9e6b5536919ba7193bb266419e0522a7b5582940402b0674208d335ab63080ebc66a84237371dab66c63fde2e684296c7471c27ec3804eddbcd5068832956191ef5b90401ac3e5cf4aa26dd8123b56cf63922f538dd46ccc139c0c293c553d9c5759aa5979d6cd81c8ae6361562ac304549b2220b8a718c376a7914a2914446a366f98014aef806a3846f7cfbd41a9a1671e5ab7ad1551864d61c0de5d68457a8b8040fad084cef34d55fb201bd48ed50dd46a256c30ac2b5d52255c16c7d2a73aa463f881ad9caeac71aa328caf72dc90aba907a5729ae69bf6726e621f213c8f4addfed68ba12291e682ee228fb5d5874a9368a671b9ce29454ba8d91d36e76e7313f287d3daa11c8e291467ccd96c7ad5c8a3f2d01354252436e1ce2a75b81280437e1506c59790e78e94d594f3ce6b3352d464823296881e53fde3c0ac4d3f56d656e0fdba28a4889ea8b822a9444ced12e4d4df692475ac88eed5d030e01ed4e375c7d2aec41a2f31c72dfad5ab5bd789873c5717aadceab3b84b1616f17566032c7fc2a6d2af6f607115e3f98a47dea2c07697f7715e5994907cc395359319f9698d7485000dc9a9117e418a96229cb1ee523d6b2a582e2263e53b2fd2b649f5e950b81c9c54a3531824ccf99b25bd69edb881c631e9571f68e7155df38f96b4467262c470315333ec5e4e2aa2162467b1ab0f229ea3eb54473019188e066a26b39a6704b151e80d598991bb62ad2327140ee36cec0a302c4fe26b471b7806a3471d8d4959b02a374aa6ec7775ef451528d5ec47313511fbc28a2b4463d4251b718e39a30334514c4498c2714464f1cd1453045e563f2f3daa7dc7d68a2a181ffd9),
(5, 46, 0xffd8ffe000104a46494600010101006000600000ffe102ec4578696600004d4d002a000000080004013b00020000000b0000014a8769000400000001000001569c9d000100000016000002ceea1c00070000010c0000003e000000001cea00000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004d41524b204c4f554953000000059003000200000014000002a49004000200000014000002b8929100020000000331320000929200020000000331320000ea1c00070000010c00000198000000001cea0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000323032343a30313a32352031333a30393a323400323032343a30313a32352031333a30393a32340000004d00410052004b0020004c004f005500490053000000ffe1041d687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f003c3f787061636b657420626567696e3d27efbbbf272069643d2757354d304d7043656869487a7265537a4e54637a6b633964273f3e0d0a3c783a786d706d65746120786d6c6e733a783d2261646f62653a6e733a6d6574612f223e3c7264663a52444620786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f222f3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a786d703d22687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f223e3c786d703a437265617465446174653e323032342d30312d32355431333a30393a32342e3131353c2f786d703a437265617465446174653e3c2f7264663a4465736372697074696f6e3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f223e3c64633a63726561746f723e3c7264663a53657120786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a6c693e4d41524b204c4f5549533c2f7264663a6c693e3c2f7264663a5365713e0d0a0909093c2f64633a63726561746f723e3c2f7264663a4465736372697074696f6e3e3c2f7264663a5244463e3c2f783a786d706d6574613e0d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c3f787061636b657420656e643d2777273f3effdb00430007050506050407060506080707080a110b0a09090a150f100c1118151a19181518171b1e27211b1d251d1718222e222528292b2c2b1a202f332f2a32272a2b2affdb0043010708080a090a140b0b142a1c181c2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2affc0001108002e002703012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00d2834e8ed9708b8abf696ff365855858958f22ac6c11af4ae23d52adc2623358f2c672462b727fba73c8acf7407eb40cc89ac5e4f990ec27ae28ad78d7b1a295da158d1b42c5c6eab532e5718aa03514ce7001a735f0619cd6b142ea3e442579aa522e0e2a537cbdcd462ee26ceea4ca2ab5c88db0dc51506a12c522e54639a2b2033351d37521279b6574cb8390a790688b50b88a354bb4d9277c1e0d749fbb3c106a8dd69893f2303ea2ad3b06e60df6aed0425a305dfb2e6b9c49fc4d737c245b8f2e227889578c5770be1fb766cbf38ab91594308c46a0607a53bdc663dac3753006eb8e3eed15b120028a44dcffd9);

-- --------------------------------------------------------

--
-- Table structure for table `tbl_reyes`
--

DROP TABLE IF EXISTS `tbl_reyes`;
CREATE TABLE IF NOT EXISTS `tbl_reyes` (
  `face_id` int NOT NULL AUTO_INCREMENT,
  `employee_id` int NOT NULL,
  `reyes` blob NOT NULL,
  PRIMARY KEY (`face_id`),
  KEY `employee_id` (`employee_id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `tbl_reyes`
--

INSERT INTO `tbl_reyes` (`face_id`, `employee_id`, `reyes`) VALUES
(3, 45, 0xffd8ffe000104a46494600010101006000600000ffe102ec4578696600004d4d002a000000080004013b00020000000b0000014a8769000400000001000001569c9d000100000016000002ceea1c00070000010c0000003e000000001cea00000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004d41524b204c4f554953000000059003000200000014000002a49004000200000014000002b8929100020000000332390000929200020000000332390000ea1c00070000010c00000198000000001cea0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000323032343a30313a32342032303a34303a343400323032343a30313a32342032303a34303a34340000004d00410052004b0020004c004f005500490053000000ffe1041d687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f003c3f787061636b657420626567696e3d27efbbbf272069643d2757354d304d7043656869487a7265537a4e54637a6b633964273f3e0d0a3c783a786d706d65746120786d6c6e733a783d2261646f62653a6e733a6d6574612f223e3c7264663a52444620786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f222f3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a786d703d22687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f223e3c786d703a437265617465446174653e323032342d30312d32345432303a34303a34342e3238393c2f786d703a437265617465446174653e3c2f7264663a4465736372697074696f6e3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f223e3c64633a63726561746f723e3c7264663a53657120786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a6c693e4d41524b204c4f5549533c2f7264663a6c693e3c2f7264663a5365713e0d0a0909093c2f64633a63726561746f723e3c2f7264663a4465736372697074696f6e3e3c2f7264663a5244463e3c2f783a786d706d6574613e0d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c3f787061636b657420656e643d2777273f3effdb00430007050506050407060506080707080a110b0a09090a150f100c1118151a19181518171b1e27211b1d251d1718222e222528292b2c2b1a202f332f2a32272a2b2affdb0043010708080a090a140b0b142a1c181c2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2affc0001108001f003b03012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00b84f3485828eb430c024d635ddf4cced15a738fbcfe86bcb49b7a1efca4a3ab367ed0898dec07e352add211f2ab37be2bcd6ff0054d523bf68a37e871903a1a85f52d7612be74b2a2b0040c86cfa7435b7b19330f6e8f5117401e6293f2a9127490e0641f715e7f61ae6aa11817de50f21856bdaf8be11208efa3f2cf4c8e6b3953922a356323b354f9723934f0c31c8aa163a8dbdc2ab5bca1948e99abff29e6b9ddcd0c7752d0b85fbdb4e3eb58f6d6d736643b462423ef73d4d6faa75a8e48724d6f19388e5152d19c1eb7a55edcdf3dd5a40e0c87e601b04565ae97aac7214712e3a601e0d7a434041e293c842df38cfe15aaaccc5e1e2ce73478dec34d687c9df34bf7998531fc34f73279801c93f366bab8e18ff008540fc2ad451f4a875a43f651461695a44d66401c7a1ae9e30c235ddd71cd2c5180738ab1b6b9e4eeee69b1fffd9),
(4, 45, 0xffd8ffe000104a46494600010101006000600000ffe102ec4578696600004d4d002a000000080004013b00020000000b0000014a8769000400000001000001569c9d000100000016000002ceea1c00070000010c0000003e000000001cea00000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004d41524b204c4f554953000000059003000200000014000002a49004000200000014000002b8929100020000000332390000929200020000000332390000ea1c00070000010c00000198000000001cea0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000323032343a30313a32342032303a34303a343400323032343a30313a32342032303a34303a34340000004d00410052004b0020004c004f005500490053000000ffe1041d687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f003c3f787061636b657420626567696e3d27efbbbf272069643d2757354d304d7043656869487a7265537a4e54637a6b633964273f3e0d0a3c783a786d706d65746120786d6c6e733a783d2261646f62653a6e733a6d6574612f223e3c7264663a52444620786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f222f3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a786d703d22687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f223e3c786d703a437265617465446174653e323032342d30312d32345432303a34303a34342e3238393c2f786d703a437265617465446174653e3c2f7264663a4465736372697074696f6e3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f223e3c64633a63726561746f723e3c7264663a53657120786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a6c693e4d41524b204c4f5549533c2f7264663a6c693e3c2f7264663a5365713e0d0a0909093c2f64633a63726561746f723e3c2f7264663a4465736372697074696f6e3e3c2f7264663a5244463e3c2f783a786d706d6574613e0d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c3f787061636b657420656e643d2777273f3effdb00430007050506050407060506080707080a110b0a09090a150f100c1118151a19181518171b1e27211b1d251d1718222e222528292b2c2b1a202f332f2a32272a2b2affdb0043010708080a090a140b0b142a1c181c2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2affc0001108001f003b03012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00b84f3485828eb430c024d635ddf4cced15a738fbcfe86bcb49b7a1efca4a3ab367ed0898dec07e352add211f2ab37be2bcd6ff0054d523bf68a37e871903a1a85f52d7612be74b2a2b0040c86cfa7435b7b19330f6e8f5117401e6293f2a9127490e0641f715e7f61ae6aa11817de50f21856bdaf8be11208efa3f2cf4c8e6b3953922a356323b354f9723934f0c31c8aa163a8dbdc2ab5bca1948e99abff29e6b9ddcd0c7752d0b85fbdb4e3eb58f6d6d736643b462423ef73d4d6faa75a8e48724d6f19388e5152d19c1eb7a55edcdf3dd5a40e0c87e601b04565ae97aac7214712e3a601e0d7a434041e293c842df38cfe15aaaccc5e1e2ce73478dec34d687c9df34bf7998531fc34f73279801c93f366bab8e18ff008540fc2ad451f4a875a43f651461695a44d66401c7a1ae9e30c235ddd71cd2c5180738ab1b6b9e4eeee69b1fffd9),
(5, 46, 0xffd8ffe000104a46494600010101006000600000ffe102ec4578696600004d4d002a000000080004013b00020000000b0000014a8769000400000001000001569c9d000100000016000002ceea1c00070000010c0000003e000000001cea00000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004d41524b204c4f554953000000059003000200000014000002a49004000200000014000002b8929100020000000333300000929200020000000333300000ea1c00070000010c00000198000000001cea0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000323032343a30313a32352031333a30393a303300323032343a30313a32352031333a30393a30330000004d00410052004b0020004c004f005500490053000000ffe1041d687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f003c3f787061636b657420626567696e3d27efbbbf272069643d2757354d304d7043656869487a7265537a4e54637a6b633964273f3e0d0a3c783a786d706d65746120786d6c6e733a783d2261646f62653a6e733a6d6574612f223e3c7264663a52444620786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f222f3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a786d703d22687474703a2f2f6e732e61646f62652e636f6d2f7861702f312e302f223e3c786d703a437265617465446174653e323032342d30312d32355431333a30393a30332e3239373c2f786d703a437265617465446174653e3c2f7264663a4465736372697074696f6e3e3c7264663a4465736372697074696f6e207264663a61626f75743d22757569643a66616635626464352d626133642d313164612d616433312d6433336437353138326631622220786d6c6e733a64633d22687474703a2f2f7075726c2e6f72672f64632f656c656d656e74732f312e312f223e3c64633a63726561746f723e3c7264663a53657120786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e3c7264663a6c693e4d41524b204c4f5549533c2f7264663a6c693e3c2f7264663a5365713e0d0a0909093c2f64633a63726561746f723e3c2f7264663a4465736372697074696f6e3e3c2f7264663a5244463e3c2f783a786d706d6574613e0d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c3f787061636b657420656e643d2777273f3effdb00430007050506050407060506080707080a110b0a09090a150f100c1118151a19181518171b1e27211b1d251d1718222e222528292b2c2b1a202f332f2a32272a2b2affdb0043010708080a090a140b0b142a1c181c2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2affc00011080014002c03012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00a2cea324f4f5ac7bff0014c767b85ba872bd5bae2a7f105bdfcb125a69a9cbf32484e303d0547a5696967632dbddd8f99e6a95690105b9ae78453dcf42a36b639e7f8877a2e19102e476dbd855ab4f8897123289914a9f4e2b226f066a2f7cef1aa856f93730e718c56849e0cb892ce2858468231f780e4d68d412315ce7516de2382fe2ca361bd0d67dec88f7049c74aa1a7f86ae6cfacad8f5abcda5cbbbe6393eb58356d8d6ceda9d6cf12c91fcd9cfa8358770cf6f3ed49188ff0068e68a2a11b21eb71214fbd576cd04ee3cc24d14512d866c7d9a20b80b50496d16f3f2d1452e82ea7fffd9);

-- --------------------------------------------------------

--
-- Table structure for table `tbl_transac`
--

DROP TABLE IF EXISTS `tbl_transac`;
CREATE TABLE IF NOT EXISTS `tbl_transac` (
  `id` int NOT NULL AUTO_INCREMENT,
  `transaction_id` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `employee_id` int NOT NULL,
  `face_image` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `eyebrows_perc` decimal(10,2) NOT NULL,
  `leyes_perc` decimal(10,2) NOT NULL,
  `reyes_perc` decimal(10,2) NOT NULL,
  `nose_perc` decimal(10,2) NOT NULL,
  `mouth_perc` decimal(10,2) NOT NULL,
  `created_At` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `overall_perc` decimal(10,2) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `employee_id` (`employee_id`)
) ENGINE=InnoDB AUTO_INCREMENT=29 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `tbl_transac`
--

INSERT INTO `tbl_transac` (`id`, `transaction_id`, `employee_id`, `face_image`, `eyebrows_perc`, `leyes_perc`, `reyes_perc`, `nose_perc`, `mouth_perc`, `created_At`, `overall_perc`) VALUES
(24, 'EMP_TRANS_20240126_12838a06-24a4-4a60-974a-a6a0dcb8893b', 45, '/temp/EMP_TRANS_20240126_12838a06-24a4-4a60-974a-a6a0dcb8893b.jpg', '93.82', '89.31', '91.68', '87.16', '77.64', '2024-01-26 04:15:12', '88.05'),
(25, 'EMP_TRANS_20240127_d16f6115-27f2-4bcb-9ea7-f78f5e0165cc', 45, '/temp/EMP_TRANS_20240127_d16f6115-27f2-4bcb-9ea7-f78f5e0165cc.jpg', '93.76', '85.97', '90.07', '88.93', '74.64', '2024-01-27 12:37:35', '87.00'),
(26, 'EMP_TRANS_20240127_37bd1eb9-6ffb-44e4-b584-6130658275e8', 45, '/temp/EMP_TRANS_20240127_37bd1eb9-6ffb-44e4-b584-6130658275e8.jpg', '94.53', '87.12', '90.83', '86.86', '75.87', '2024-01-27 12:49:50', '87.52'),
(27, 'EMP_TRANS_20240127_63c9b663-a177-4ffb-aee4-82345a398e6c', 45, '/temp/EMP_TRANS_20240127_63c9b663-a177-4ffb-aee4-82345a398e6c.jpg', '94.36', '86.53', '91.37', '86.01', '75.03', '2024-01-27 13:00:01', '87.27'),
(28, 'EMP_TRANS_20240127_2b2844dc-5cae-4b51-89ee-bf69d6634600', 45, '/temp/EMP_TRANS_20240127_2b2844dc-5cae-4b51-89ee-bf69d6634600.jpg', '92.78', '85.52', '89.95', '90.57', '75.84', '2024-01-27 13:23:28', '87.08');

--
-- Constraints for dumped tables
--

--
-- Constraints for table `tbl_attendrec`
--
ALTER TABLE `tbl_attendrec`
  ADD CONSTRAINT `tbl_attendrec_ibfk_1` FOREIGN KEY (`employee_id`) REFERENCES `tbl_empdata` (`employee_id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `tbl_eyebrows`
--
ALTER TABLE `tbl_eyebrows`
  ADD CONSTRAINT `tbl_eyebrows_ibfk_1` FOREIGN KEY (`employee_id`) REFERENCES `tbl_empdata` (`employee_id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `tbl_leyes`
--
ALTER TABLE `tbl_leyes`
  ADD CONSTRAINT `tbl_leyes_ibfk_1` FOREIGN KEY (`employee_id`) REFERENCES `tbl_empdata` (`employee_id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `tbl_mouth`
--
ALTER TABLE `tbl_mouth`
  ADD CONSTRAINT `tbl_mouth_ibfk_1` FOREIGN KEY (`employee_id`) REFERENCES `tbl_empdata` (`employee_id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `tbl_nose`
--
ALTER TABLE `tbl_nose`
  ADD CONSTRAINT `tbl_nose_ibfk_1` FOREIGN KEY (`employee_id`) REFERENCES `tbl_empdata` (`employee_id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `tbl_reyes`
--
ALTER TABLE `tbl_reyes`
  ADD CONSTRAINT `tbl_reyes_ibfk_1` FOREIGN KEY (`employee_id`) REFERENCES `tbl_empdata` (`employee_id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `tbl_transac`
--
ALTER TABLE `tbl_transac`
  ADD CONSTRAINT `tbl_transac_ibfk_1` FOREIGN KEY (`employee_id`) REFERENCES `tbl_empdata` (`employee_id`) ON DELETE CASCADE ON UPDATE CASCADE;
--
-- Database: `flask_db`
--
CREATE DATABASE IF NOT EXISTS `flask_db` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `flask_db`;

-- --------------------------------------------------------

--
-- Table structure for table `accs_hist`
--

DROP TABLE IF EXISTS `accs_hist`;
CREATE TABLE IF NOT EXISTS `accs_hist` (
  `accs_id` int NOT NULL AUTO_INCREMENT,
  `accs_date` date NOT NULL,
  `accs_prsn` varchar(3) NOT NULL,
  `accs_added` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`accs_id`),
  KEY `accs_date` (`accs_date`)
) ENGINE=InnoDB AUTO_INCREMENT=66 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `accs_hist`
--

INSERT INTO `accs_hist` (`accs_id`, `accs_date`, `accs_prsn`, `accs_added`) VALUES
(1, '2024-03-11', '101', '2024-03-11 12:10:12'),
(2, '2024-03-11', '101', '2024-03-11 12:10:18'),
(3, '2024-03-11', '101', '2024-03-11 12:10:25'),
(4, '2024-03-11', '101', '2024-03-11 12:10:31'),
(5, '2024-03-11', '101', '2024-03-11 12:32:43'),
(6, '2024-03-11', '101', '2024-03-11 12:39:29'),
(7, '2024-03-11', '101', '2024-03-11 12:49:33'),
(8, '2024-03-11', '101', '2024-03-11 12:49:42'),
(9, '2024-03-11', '101', '2024-03-11 12:49:53'),
(10, '2024-03-11', '101', '2024-03-11 12:51:05'),
(11, '2024-03-11', '101', '2024-03-11 12:53:16'),
(12, '2024-03-11', '101', '2024-03-11 12:55:19'),
(13, '2024-03-11', '101', '2024-03-11 12:55:35'),
(14, '2024-03-11', '101', '2024-03-11 12:55:46'),
(15, '2024-03-11', '101', '2024-03-11 12:55:55'),
(16, '2024-03-11', '101', '2024-03-11 12:56:27'),
(17, '2024-03-11', '101', '2024-03-11 12:57:07'),
(18, '2024-03-11', '101', '2024-03-11 12:57:44'),
(19, '2024-03-11', '101', '2024-03-11 12:58:07'),
(20, '2024-03-11', '101', '2024-03-11 12:58:44'),
(21, '2024-03-11', '101', '2024-03-11 12:59:10'),
(22, '2024-03-11', '101', '2024-03-11 12:59:35'),
(23, '2024-03-11', '101', '2024-03-11 13:08:47'),
(24, '2024-03-11', '101', '2024-03-11 13:08:55'),
(25, '2024-03-11', '101', '2024-03-11 13:09:07'),
(26, '2024-03-11', '101', '2024-03-11 13:09:15'),
(27, '2024-03-11', '101', '2024-03-11 13:09:23'),
(28, '2024-03-11', '101', '2024-03-11 13:09:31'),
(29, '2024-03-11', '101', '2024-03-11 13:09:43'),
(30, '2024-03-11', '101', '2024-03-11 13:10:37'),
(31, '2024-03-11', '101', '2024-03-11 13:11:19'),
(32, '2024-03-11', '101', '2024-03-11 13:11:50'),
(33, '2024-03-11', '101', '2024-03-11 13:12:02'),
(34, '2024-03-11', '101', '2024-03-11 13:12:10'),
(35, '2024-03-11', '101', '2024-03-11 13:12:21'),
(36, '2024-03-11', '101', '2024-03-11 14:01:48'),
(37, '2024-03-11', '101', '2024-03-11 14:01:54'),
(38, '2024-03-11', '101', '2024-03-11 14:02:12'),
(39, '2024-03-11', '101', '2024-03-11 14:02:21'),
(40, '2024-03-11', '101', '2024-03-11 14:02:29'),
(41, '2024-03-11', '101', '2024-03-11 14:02:41'),
(42, '2024-03-11', '101', '2024-03-11 14:02:51'),
(43, '2024-03-11', '101', '2024-03-11 14:02:57'),
(44, '2024-03-11', '101', '2024-03-11 14:03:04'),
(45, '2024-03-11', '101', '2024-03-11 14:03:19'),
(46, '2024-03-11', '101', '2024-03-11 14:03:28'),
(47, '2024-03-11', '101', '2024-03-11 14:04:11'),
(48, '2024-03-11', '101', '2024-03-11 14:04:20'),
(49, '2024-03-11', '101', '2024-03-11 14:04:26'),
(50, '2024-03-11', '101', '2024-03-11 14:04:51'),
(51, '2024-03-11', '101', '2024-03-11 14:04:57'),
(52, '2024-03-11', '101', '2024-03-11 14:05:03'),
(53, '2024-03-11', '101', '2024-03-11 14:05:10'),
(54, '2024-03-11', '101', '2024-03-11 14:05:18'),
(55, '2024-03-11', '101', '2024-03-11 14:05:29'),
(56, '2024-03-11', '101', '2024-03-11 14:05:35'),
(57, '2024-03-11', '101', '2024-03-11 14:05:57'),
(58, '2024-03-11', '101', '2024-03-11 14:06:19'),
(59, '2024-03-24', '101', '2024-03-24 16:13:46'),
(60, '2024-03-24', '101', '2024-03-24 16:13:58'),
(61, '2024-03-24', '101', '2024-03-24 16:14:05'),
(62, '2024-03-24', '101', '2024-03-24 16:14:19'),
(63, '2024-03-24', '101', '2024-03-24 16:14:37'),
(64, '2024-03-24', '101', '2024-03-24 16:14:59'),
(65, '2024-03-24', '101', '2024-03-24 16:15:16');

-- --------------------------------------------------------

--
-- Table structure for table `img_dataset`
--

DROP TABLE IF EXISTS `img_dataset`;
CREATE TABLE IF NOT EXISTS `img_dataset` (
  `img_id` int NOT NULL,
  `img_person` varchar(3) NOT NULL,
  PRIMARY KEY (`img_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `img_dataset`
--

INSERT INTO `img_dataset` (`img_id`, `img_person`) VALUES
(1, '101'),
(2, '101'),
(3, '101'),
(4, '101'),
(5, '101'),
(6, '101'),
(7, '101'),
(8, '101'),
(9, '101'),
(10, '101'),
(11, '101'),
(12, '101'),
(13, '101'),
(14, '101'),
(15, '101'),
(16, '101'),
(17, '101'),
(18, '101'),
(19, '101'),
(20, '101'),
(21, '101'),
(22, '101'),
(23, '101'),
(24, '101'),
(25, '101'),
(26, '101'),
(27, '101'),
(28, '101'),
(29, '101'),
(30, '101'),
(31, '101'),
(32, '101'),
(33, '101'),
(34, '101'),
(35, '101'),
(36, '101'),
(37, '101'),
(38, '101'),
(39, '101'),
(40, '101'),
(41, '101'),
(42, '101'),
(43, '101'),
(44, '101'),
(45, '101'),
(46, '101'),
(47, '101'),
(48, '101'),
(49, '101'),
(50, '101'),
(51, '101'),
(52, '101'),
(53, '101'),
(54, '101'),
(55, '101'),
(56, '101'),
(57, '101'),
(58, '101'),
(59, '101'),
(60, '101'),
(61, '101'),
(62, '101'),
(63, '101'),
(64, '101'),
(65, '101'),
(66, '101'),
(67, '101'),
(68, '101'),
(69, '101'),
(70, '101'),
(71, '101'),
(72, '101'),
(73, '101'),
(74, '101'),
(75, '101'),
(76, '101'),
(77, '101'),
(78, '101'),
(79, '101'),
(80, '101'),
(81, '101'),
(82, '101'),
(83, '101'),
(84, '101'),
(85, '101'),
(86, '101'),
(87, '101'),
(88, '101'),
(89, '101'),
(90, '101'),
(91, '101'),
(92, '101'),
(93, '101'),
(94, '101'),
(95, '101'),
(96, '101'),
(97, '101'),
(98, '101'),
(99, '101'),
(100, '101');

-- --------------------------------------------------------

--
-- Table structure for table `prs_mstr`
--

DROP TABLE IF EXISTS `prs_mstr`;
CREATE TABLE IF NOT EXISTS `prs_mstr` (
  `prs_nbr` varchar(3) NOT NULL,
  `prs_name` varchar(50) NOT NULL,
  `prs_skill` varchar(30) NOT NULL,
  `prs_active` varchar(1) NOT NULL DEFAULT 'Y',
  `prs_added` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`prs_nbr`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `prs_mstr`
--

INSERT INTO `prs_mstr` (`prs_nbr`, `prs_name`, `prs_skill`, `prs_active`, `prs_added`) VALUES
('101', 'Sebastian', 'SOFTWARE', 'Y', '2024-03-11 12:09:30'),
('102', 'asd asd asd asd', 'SOFTWARE', 'Y', '2024-03-24 19:08:06'),
('103', 'asd asd asd as d', 'SOFTWARE', 'Y', '2024-03-24 19:09:45');
--
-- Database: `library`
--
CREATE DATABASE IF NOT EXISTS `library` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `library`;

-- --------------------------------------------------------

--
-- Table structure for table `admin`
--

DROP TABLE IF EXISTS `admin`;
CREATE TABLE IF NOT EXISTS `admin` (
  `id` int NOT NULL AUTO_INCREMENT,
  `FullName` varchar(100) DEFAULT NULL,
  `AdminEmail` varchar(120) DEFAULT NULL,
  `UserName` varchar(100) NOT NULL,
  `Password` varchar(100) NOT NULL,
  `updationDate` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `admin`
--

INSERT INTO `admin` (`id`, `FullName`, `AdminEmail`, `UserName`, `Password`, `updationDate`) VALUES
(1, 'Kumar Pandule', 'kumarpandule@gmail.com', 'admin', 'e6e061838856bf47e1de730719fb2609', '2021-06-28 16:06:08');

-- --------------------------------------------------------

--
-- Table structure for table `tblauthors`
--

DROP TABLE IF EXISTS `tblauthors`;
CREATE TABLE IF NOT EXISTS `tblauthors` (
  `id` int NOT NULL AUTO_INCREMENT,
  `AuthorName` varchar(159) DEFAULT NULL,
  `creationDate` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `UpdationDate` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `tblauthors`
--

INSERT INTO `tblauthors` (`id`, `AuthorName`, `creationDate`, `UpdationDate`) VALUES
(1, 'Kumar Pandule', '2017-07-08 12:49:09', '2021-06-28 16:03:28'),
(2, 'Kumar', '2017-07-08 14:30:23', '2021-06-28 16:03:35'),
(3, 'Rahul', '2017-07-08 14:35:08', '2021-06-28 16:03:43'),
(4, 'HC Verma', '2017-07-08 14:35:21', NULL),
(5, 'R.D. Sharma ', '2017-07-08 14:35:36', NULL),
(9, 'fwdfrwer', '2017-07-08 15:22:03', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `tblbooks`
--

DROP TABLE IF EXISTS `tblbooks`;
CREATE TABLE IF NOT EXISTS `tblbooks` (
  `id` int NOT NULL AUTO_INCREMENT,
  `BookName` varchar(255) DEFAULT NULL,
  `CatId` int DEFAULT NULL,
  `AuthorId` int DEFAULT NULL,
  `ISBNNumber` int DEFAULT NULL,
  `BookPrice` int DEFAULT NULL,
  `RegDate` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `UpdationDate` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `tblbooks`
--

INSERT INTO `tblbooks` (`id`, `BookName`, `CatId`, `AuthorId`, `ISBNNumber`, `BookPrice`, `RegDate`, `UpdationDate`) VALUES
(1, 'PHP And MySql programming', 5, 1, 222333, 20, '2017-07-08 20:04:55', '2017-07-15 05:54:41'),
(3, 'physics', 6, 4, 1111, 15, '2017-07-08 20:17:31', '2017-07-15 06:13:17');

-- --------------------------------------------------------

--
-- Table structure for table `tblcategory`
--

DROP TABLE IF EXISTS `tblcategory`;
CREATE TABLE IF NOT EXISTS `tblcategory` (
  `id` int NOT NULL AUTO_INCREMENT,
  `CategoryName` varchar(150) DEFAULT NULL,
  `Status` int DEFAULT NULL,
  `CreationDate` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `UpdationDate` timestamp NULL DEFAULT '0000-00-00 00:00:00' ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `tblcategory`
--

INSERT INTO `tblcategory` (`id`, `CategoryName`, `Status`, `CreationDate`, `UpdationDate`) VALUES
(4, 'Romantic', 1, '2017-07-04 18:35:25', '2017-07-06 16:00:42'),
(5, 'Technology', 1, '2017-07-04 18:35:39', '2017-07-08 17:13:03'),
(6, 'Science', 1, '2017-07-04 18:35:55', '0000-00-00 00:00:00'),
(7, 'Management', 0, '2017-07-04 18:36:16', '0000-00-00 00:00:00');

-- --------------------------------------------------------

--
-- Table structure for table `tblissuedbookdetails`
--

DROP TABLE IF EXISTS `tblissuedbookdetails`;
CREATE TABLE IF NOT EXISTS `tblissuedbookdetails` (
  `id` int NOT NULL AUTO_INCREMENT,
  `BookId` int DEFAULT NULL,
  `StudentID` varchar(150) DEFAULT NULL,
  `IssuesDate` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `ReturnDate` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  `RetrunStatus` int DEFAULT NULL,
  `fine` int DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `tblissuedbookdetails`
--

INSERT INTO `tblissuedbookdetails` (`id`, `BookId`, `StudentID`, `IssuesDate`, `ReturnDate`, `RetrunStatus`, `fine`) VALUES
(1, 1, 'SID002', '2017-07-15 06:09:47', '2017-07-15 11:15:20', 1, 0),
(2, 1, 'SID002', '2017-07-15 06:12:27', '2017-07-15 11:15:23', 1, 5),
(3, 3, 'SID002', '2017-07-15 06:13:40', NULL, 0, NULL),
(4, 3, 'SID002', '2017-07-15 06:23:23', '2017-07-15 11:22:29', 1, 2),
(5, 1, 'SID009', '2017-07-15 10:59:26', NULL, 0, NULL),
(6, 3, 'SID011', '2017-07-15 18:02:55', NULL, 0, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `tblstudents`
--

DROP TABLE IF EXISTS `tblstudents`;
CREATE TABLE IF NOT EXISTS `tblstudents` (
  `id` int NOT NULL AUTO_INCREMENT,
  `StudentId` varchar(100) DEFAULT NULL,
  `FullName` varchar(120) DEFAULT NULL,
  `EmailId` varchar(120) DEFAULT NULL,
  `MobileNumber` char(11) DEFAULT NULL,
  `Password` varchar(120) DEFAULT NULL,
  `Status` int DEFAULT NULL,
  `RegDate` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `UpdationDate` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `StudentId` (`StudentId`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `tblstudents`
--

INSERT INTO `tblstudents` (`id`, `StudentId`, `FullName`, `EmailId`, `MobileNumber`, `Password`, `Status`, `RegDate`, `UpdationDate`) VALUES
(1, 'SID002', 'Anuj kumar', 'anuj.lpu1@gmail.com', '9865472555', 'f925916e2754e5e03f75dd58a5733251', 1, '2017-07-11 15:37:05', '2017-07-15 18:26:21'),
(4, 'SID005', 'sdfsd', 'csfsd@dfsfks.com', '8569710025', '92228410fc8b872914e023160cf4ae8f', 0, '2017-07-11 15:41:27', '2017-07-15 17:43:03'),
(8, 'SID009', 'test', 'test@gmail.com', '2359874527', 'f925916e2754e5e03f75dd58a5733251', 1, '2017-07-11 15:58:28', '2017-07-15 13:42:44'),
(9, 'SID010', 'Amit', 'amit@gmail.com', '8585856224', 'f925916e2754e5e03f75dd58a5733251', 1, '2017-07-15 13:40:30', NULL),
(10, 'SID011', 'Sarita Pandey', 'sarita@gmail.com', '4672423754', 'f925916e2754e5e03f75dd58a5733251', 1, '2017-07-15 18:00:59', NULL);
--
-- Database: `peopledb`
--
CREATE DATABASE IF NOT EXISTS `peopledb` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `peopledb`;

-- --------------------------------------------------------

--
-- Table structure for table `people`
--

DROP TABLE IF EXISTS `people`;
CREATE TABLE IF NOT EXISTS `people` (
  `people_id` int NOT NULL AUTO_INCREMENT,
  `first_name` varchar(30) NOT NULL,
  `last_name` varchar(30) NOT NULL,
  `mid_name` varchar(30) NOT NULL,
  `address` varchar(30) NOT NULL,
  `contact` varchar(30) NOT NULL,
  `comment` text NOT NULL,
  PRIMARY KEY (`people_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `people`
--

INSERT INTO `people` (`people_id`, `first_name`, `last_name`, `mid_name`, `address`, `contact`, `comment`) VALUES
(4, 'Jet', 'Sebastian', 'Dela Cruz', '14 Industrial Ave. Potrero Mal', '9564629898', 'NIGGGGG');
--
-- Database: `phplogin`
--
CREATE DATABASE IF NOT EXISTS `phplogin` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE `phplogin`;

-- --------------------------------------------------------

--
-- Table structure for table `accounts`
--

DROP TABLE IF EXISTS `accounts`;
CREATE TABLE IF NOT EXISTS `accounts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(100) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3;

--
-- Dumping data for table `accounts`
--

INSERT INTO `accounts` (`id`, `username`, `password`, `email`) VALUES
(1, 'test', '$2y$10$SfhYIDtn.iOuCW7zfoFLuuZHX6lja4lF4XA4JqNmpiH/.P3zB8JCa', 'test@test.com');

-- --------------------------------------------------------

--
-- Table structure for table `user_tokens`
--

DROP TABLE IF EXISTS `user_tokens`;
CREATE TABLE IF NOT EXISTS `user_tokens` (
  `id` int NOT NULL AUTO_INCREMENT,
  `selector` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `hashed_validator` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `user_id` int NOT NULL,
  `expiry` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_user_id` (`user_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
--
-- Database: `pmci`
--
CREATE DATABASE IF NOT EXISTS `pmci` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE `pmci`;

-- --------------------------------------------------------

--
-- Table structure for table `account`
--

DROP TABLE IF EXISTS `account`;
CREATE TABLE IF NOT EXISTS `account` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `password` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `email` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `name` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `account`
--

INSERT INTO `account` (`id`, `username`, `password`, `email`, `name`) VALUES
(1, 'admin', '$2y$10$IIRit1a9NSWy0I6QBG4fW.w0aF2yqLyFrK6DgDxPIF8vn7gsrcykS', 'a@a.comasdasdasdas', 'isa assd'),
(2, '$username', '$2y$10$2h6kZnSjT5fYOTitENu5Yus4KhbT/QszZSqhF59wu7pXjPmBppRje', '$email', '$name'),
(3, 'admin3', '$2y$10$OvlrzTV5IzZy1Ier7YsR2OY1dpmm7XFqQOjb2aTTqqUyn37WKI7pC', 'admin2@gmail.com', 'name'),
(4, 'admin5', '$2y$10$h8bkXs0UMW5rkmgr17Jveu.gYzKUQQykVpCvmFDJsuyOCUfzmMSiu', 'admin5@gmail.com', 'name'),
(5, 'admin11', '$2y$10$Q/hqgxRPMc4mS6qs3P9E.uYnVtDYOYy6osI/adk9Vb9P5/hFD7qfO', 'admin11@gmail.com', 'name'),
(6, 'asdasdasd', '$2y$10$y.afAYcjq8m99FBucnr.A.M4L9oRC776eIHA5F29wlxWFkmM/Lo5C', 'asdasd@asd.c', 'asdasd'),
(7, 'adminadmin', '$2y$10$iMoaOv4zDm/dYer6rJ.JLe/TbaB5OoiXhOPFYy6lG3xzBivqY/tUW', 'ads@gmail.com', 'Jet Sebastian');

-- --------------------------------------------------------

--
-- Table structure for table `enrollment`
--

DROP TABLE IF EXISTS `enrollment`;
CREATE TABLE IF NOT EXISTS `enrollment` (
  `id` int NOT NULL,
  `name` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `age` int NOT NULL,
  `bday` date NOT NULL,
  `address` text COLLATE utf8mb4_general_ci NOT NULL,
  `contact` int NOT NULL,
  `email` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `level` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `transfer_school` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `transfer_sy` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `referral` varchar(155) COLLATE utf8mb4_general_ci NOT NULL,
  `pic` int NOT NULL,
  `psa` int NOT NULL,
  `good_moral` int NOT NULL,
  `card` int NOT NULL,
  `ecd` int NOT NULL,
  `fee` int NOT NULL,
  `date` date NOT NULL,
  `time` varchar(255) COLLATE utf8mb4_general_ci NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `holiday`
--

DROP TABLE IF EXISTS `holiday`;
CREATE TABLE IF NOT EXISTS `holiday` (
  `id` int NOT NULL AUTO_INCREMENT,
  `holiday_name` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `holiday_date` date NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `news`
--

DROP TABLE IF EXISTS `news`;
CREATE TABLE IF NOT EXISTS `news` (
  `id` int NOT NULL AUTO_INCREMENT,
  `image_path` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
  `title` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
  `description` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci,
  `reg_date` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `news`
--

INSERT INTO `news` (`id`, `image_path`, `title`, `description`, `reg_date`) VALUES
(1, 'newspics/1.png', '11122 asdas d', 'asd ad ad aa sdasd a asdad asd', '2024-03-07 00:00:00'),
(2, 'newspics/2.png', 'a dasd a', 's asd ad asd ', '2024-03-06 00:00:00'),
(3, 'newspics/3.png', 'df sf s', 'df sdf sdf ', '2024-03-12 00:00:00');
--
-- Database: `rotary`
--
CREATE DATABASE IF NOT EXISTS `rotary` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `rotary`;

-- --------------------------------------------------------

--
-- Table structure for table `account`
--

DROP TABLE IF EXISTS `account`;
CREATE TABLE IF NOT EXISTS `account` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `account`
--

INSERT INTO `account` (`id`, `name`, `username`, `password`, `email`) VALUES
(1, 'Admin A.', 'admin', '$2a$12$SMVQU15U.v/5wkZmgHsKLOoKFYRayncTUFtSd9fs4yHOce1be.DI2', 'admin@gmail.com');
--
-- Database: `testing`
--
CREATE DATABASE IF NOT EXISTS `testing` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `testing`;

-- --------------------------------------------------------

--
-- Table structure for table `customer_table`
--

DROP TABLE IF EXISTS `customer_table`;
CREATE TABLE IF NOT EXISTS `customer_table` (
  `customer_id` int NOT NULL AUTO_INCREMENT,
  `customer_first_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `customer_last_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `customer_email` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `customer_gender` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  PRIMARY KEY (`customer_id`)
) ENGINE=MyISAM AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `customer_table`
--

INSERT INTO `customer_table` (`customer_id`, `customer_first_name`, `customer_last_name`, `customer_email`, `customer_gender`) VALUES
(1, 'N', 'I', 'ga@a.com', 'Male'),
(2, 'sdfsdf', 'sfsf', 'sdfsdf@sad.asd', 'Male'),
(3, 'N', 'I', 'ga@a.com', 'Male'),
(4, 'sdfsdf', 'sfsf', 'sdfsdf@sad.asd', 'Male'),
(5, 'N', 'I', 'ga@a.com', 'Male'),
(6, 'sdfsdf', 'sfsf', 'sdfsdf@sad.asd', 'Male'),
(7, 'N', 'I', 'ga@a.com', 'Male'),
(8, 'sdfsdf', 'sfsfhjghj', 'sdfsdf@sad.asd', 'Male');
--
-- Database: `wt_database`
--
CREATE DATABASE IF NOT EXISTS `wt_database` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `wt_database`;

-- --------------------------------------------------------

--
-- Table structure for table `book`
--

DROP TABLE IF EXISTS `book`;
CREATE TABLE IF NOT EXISTS `book` (
  `Username` varchar(30) NOT NULL,
  `Fname` varchar(30) NOT NULL,
  `Gender` varchar(10) NOT NULL,
  `CID` int NOT NULL,
  `DID` int NOT NULL,
  `DOV` date NOT NULL,
  `Timestamp` datetime NOT NULL,
  `Status` varchar(100) NOT NULL,
  PRIMARY KEY (`Username`,`Fname`,`DOV`,`Timestamp`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `book`
--

INSERT INTO `book` (`Username`, `Fname`, `Gender`, `CID`, `DID`, `DOV`, `Timestamp`, `Status`) VALUES
('user', 'patient', 'male', 1, 1, '2017-11-08', '2017-11-05 16:43:48', 'Booking Registered.Wait for the update'),
('sebastian200x', 'Jet Sebastian', 'male', 1, 1, '2024-03-26', '2024-03-21 02:00:59', 'Booking Registered.Wait for the update');

-- --------------------------------------------------------

--
-- Table structure for table `clinic`
--

DROP TABLE IF EXISTS `clinic`;
CREATE TABLE IF NOT EXISTS `clinic` (
  `cid` int NOT NULL,
  `name` varchar(30) NOT NULL,
  `address` varchar(100) NOT NULL,
  `town` varchar(30) NOT NULL,
  `city` varchar(30) NOT NULL,
  `contact` bigint NOT NULL,
  `mid` varchar(5) DEFAULT NULL,
  PRIMARY KEY (`cid`,`name`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `clinic`
--

INSERT INTO `clinic` (`cid`, `name`, `address`, `town`, `city`, `contact`, `mid`) VALUES
(1, 'Clinic', 'XYZ apartment, CST', 'CST', 'Mumbai', 9999988888, '1');

-- --------------------------------------------------------

--
-- Table structure for table `doctor`
--

DROP TABLE IF EXISTS `doctor`;
CREATE TABLE IF NOT EXISTS `doctor` (
  `did` int NOT NULL,
  `name` varchar(30) NOT NULL,
  `gender` varchar(30) NOT NULL,
  `dob` date NOT NULL,
  `experience` int NOT NULL,
  `specialization` varchar(30) NOT NULL,
  `contact` bigint NOT NULL,
  `address` varchar(100) NOT NULL,
  `username` varchar(30) NOT NULL,
  `password` varchar(30) NOT NULL,
  `region` varchar(30) NOT NULL,
  PRIMARY KEY (`did`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `doctor`
--

INSERT INTO `doctor` (`did`, `name`, `gender`, `dob`, `experience`, `specialization`, `contact`, `address`, `username`, `password`, `region`) VALUES
(1, 'doctor', 'male', '1980-01-01', 10, 'Orthodontist', 9999999999, 'XYZ tower, CST', 'doctor', 'doctor', 'Mumbai');

-- --------------------------------------------------------

--
-- Table structure for table `doctor_availability`
--

DROP TABLE IF EXISTS `doctor_availability`;
CREATE TABLE IF NOT EXISTS `doctor_availability` (
  `cid` int NOT NULL,
  `did` int NOT NULL,
  `day` varchar(50) NOT NULL,
  `starttime` time NOT NULL,
  `endtime` time NOT NULL,
  PRIMARY KEY (`cid`,`did`,`day`,`starttime`,`endtime`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `doctor_availability`
--

INSERT INTO `doctor_availability` (`cid`, `did`, `day`, `starttime`, `endtime`) VALUES
(1, 1, 'Friday', '14:00:00', '18:00:00'),
(1, 1, 'Monday', '14:00:00', '18:00:00'),
(1, 1, 'Thursday', '14:00:00', '18:00:00'),
(1, 1, 'Tuesday', '14:00:00', '18:00:00'),
(1, 1, 'Wednesday', '14:00:00', '18:00:00');

-- --------------------------------------------------------

--
-- Table structure for table `manager`
--

DROP TABLE IF EXISTS `manager`;
CREATE TABLE IF NOT EXISTS `manager` (
  `mid` int NOT NULL,
  `name` varchar(30) NOT NULL,
  `gender` varchar(30) NOT NULL,
  `dob` date NOT NULL,
  `contact` bigint NOT NULL,
  `address` varchar(100) NOT NULL,
  `username` varchar(30) NOT NULL,
  `password` varchar(30) NOT NULL,
  `region` varchar(30) NOT NULL,
  PRIMARY KEY (`mid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `manager`
--

INSERT INTO `manager` (`mid`, `name`, `gender`, `dob`, `contact`, `address`, `username`, `password`, `region`) VALUES
(1, 'Manager', 'male', '1990-01-01', 8888899999, 'XYZ complex CST', 'manager', 'manager', 'Mumbai');

-- --------------------------------------------------------

--
-- Table structure for table `manager_clinic`
--

DROP TABLE IF EXISTS `manager_clinic`;
CREATE TABLE IF NOT EXISTS `manager_clinic` (
  `cid` int NOT NULL,
  `mid` int NOT NULL,
  PRIMARY KEY (`cid`,`mid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `manager_clinic`
--

INSERT INTO `manager_clinic` (`cid`, `mid`) VALUES
(1, 1);

-- --------------------------------------------------------

--
-- Table structure for table `patient`
--

DROP TABLE IF EXISTS `patient`;
CREATE TABLE IF NOT EXISTS `patient` (
  `name` varchar(30) NOT NULL,
  `gender` varchar(30) NOT NULL,
  `dob` date NOT NULL,
  `contact` bigint NOT NULL,
  `email` varchar(30) NOT NULL,
  `username` varchar(20) NOT NULL,
  `password` varchar(20) NOT NULL,
  PRIMARY KEY (`email`,`username`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `patient`
--

INSERT INTO `patient` (`name`, `gender`, `dob`, `contact`, `email`, `username`, `password`) VALUES
('user', 'male', '1985-01-01', 7897897897, 'user@test.com', 'user', 'user'),
('Jet Sebastian', 'male', '2002-01-02', 9564629898, 'jetsebastian4@gmail.com', 'sebastian200x', '1234');
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
