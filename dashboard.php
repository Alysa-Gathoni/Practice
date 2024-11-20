<?php
require "load.php";
$ObjGlob->checksignin();
$ObjGlob->verify_profile();
$ObjLayouts->heading();
$ObjMenus->main_menu();
$ObjHeadings->main_banner();
$ObjCont->main_content();
$ObjCont->side_bar();
$ObjLayouts->footer();