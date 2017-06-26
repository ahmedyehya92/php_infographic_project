<?php

require_once '../include/DbHandler.php';
require_once '../include/PassHash.php';
require '.././libs/Slim/Slim.php';

\Slim\Slim::registerAutoloader();

$app = new \Slim\Slim();

// User id from db - Global Variable
$user_id = NULL;

/**
 * Adding Middle Layer to authenticate every request
 * Checking if the request has valid api key in the 'Authorization' header
 */
function authenticate(\Slim\Route $route) {
    // Getting request headers
    $headers = apache_request_headers();
    $response = array();
    $app = \Slim\Slim::getInstance();

    // Verifying Authorization Header
    if (isset($headers['Authorization'])) {
        $db = new DbHandler();

        // get the api key
        $api_key = $headers['Authorization'];
        // validating api key
        if (!$db->isValidApiKey($api_key)) {
            // api key is not present in users table
            $response["error"] = true;
            $response["message"] = "Access Denied. Invalid Api key";
            echoRespnse(401, $response);
            $app->stop();
        } else {
            global $user_id;
            // get user primary key id
            $user_id = $db->getUserId($api_key);
        }
    } else {
        // api key is missing in header
        $response["error"] = true;
        $response["message"] = "Api key is misssing";
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * ----------- METHODS WITHOUT AUTHENTICATION ---------------------------------
 */
/**
 * User Registration
 * url - /register
 * method - POST
 * params - name, email, password
 */
$app->post('/register', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('name', 'email', 'password'));

            $response = array();

            // reading post params
            $name = $app->request->post('name');
            $email = $app->request->post('email');
            $password = $app->request->post('password');

            // validating email address
            validateEmail($email);

            $db = new DbHandler();
            $res = $db->createUser($name, $email, $password);

            if (($res != USER_CREATE_FAILED)&&($res != USER_ALREADY_EXISTED)) {
                $response["error"] = FALSE;
            $response["apiKey"] = $res["api_key"];
            $response["user"]["id"] = $res["id"];
            $response["user"]["name"] = $res["name"];
            $response["user"]["email"] = $res["email"];
            $response["user"]["created_at"] = $res["created_at"];
            
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "خطأ في التسجيل حاول مرة أخرى";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "هذا الإيميل تم التسجيل به سابقا";
            }
            // echo json response
            echoRespnse(201, $response);
        });

/**
 * User Login
 * url - /login
 * method - POST
 * params - email, password
 */
$app->post('/login', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('email', 'password'));

            // reading post params
            $email = $app->request()->post('email');
            $password = $app->request()->post('password');
            $response = array();

            $db = new DbHandler();
            // check for correct email and password
            if ($db->checkLogin($email, $password)) {
                // get the user by email
                $user = $db->getUserByEmail($email);

                if ($user != NULL) {
                    $response["error"] = false;
                    $response['apiKey'] = $user['api_key'];
                    $response["user"]["id"] = $user["id"];
                    $response["user"]['name'] = $user['name'];
                    $response["user"]['email'] = $user['email'];
                    $response["user"]['created_at'] = $user['created_at'];
                } else {
                    // unknown error occurred
                    $response['error'] = true;
                    $response['message'] = "حدث خطأ في الإتصال حاول مرة أخرى";
                }
            } else {
                // user credentials are wrong
                $response['error'] = true;
                $response['message'] = 'الرجاء إدخال البيانات بصورة صحيحة';
            }

            echoRespnse(200, $response);
        });

/*
 * ------------------------ METHODS WITH AUTHENTICATION ------------------------
 */

/**
 * Listing all tasks of particual user
 * method GET
 * url /tasks          
 */
 //------------------------------------------------------------       
    $app->post('/categories', 'authenticate', function() use ($app) {
            global $categories;
            $response = array();
            $categories = $app->request->post('categories');
            $db = new DbHandler();
            $result = $db->getCategories($categories);
            $response["error"] = false;
            $response["categories"] = array();
            
            while ($category = $result->fetch_assoc()) {
                $tmp = array();
             
                $tmp["id"] = $category["id"];
                $tmp["category"] = $category["category"];
                $tmp["icon"] = $category["icon"];
                
                
                
                array_push($response["categories"], $tmp);
            }
            echoRespnse(200, $response);
        });
        
//------------------------------------------------------

        
       

        
        
        
        $app->post('/categoriesfollowing', 'authenticate', function() use ($app) {
            global $categories;
            global $user_id;
            global $category_id;
            $response = array();
            $categories = $app->request->post('categories');
            $user_id = $app->request->post('userid');
            
            $db = new DbHandler();
            $result = $db->getCategories($categories);
            $response["error"] = false;
            $response["categories"] = array();
            
            while ($category = $result->fetch_assoc()) {
                $tmp = array();
             
                $category_id = $category["id"];
                $db2 = new DbHandler();
                $result2 = $db2->isFollowed($user_id, $category_id);
                if ($result2['user_id'] != [])
                {
                    $isFollowed = true;
                   
                    
                }
                else {
                $isFollowed = false;
                }
                $tmp["isFollowed"] = $isFollowed;
                $tmp["id"] = $category["id"];
                $tmp["category"] = $category["category"];
                
                
                
                array_push($response["categories"], $tmp);
            }
            echoRespnse(200, $response);
        });

$app->post('/infographicscatg','authenticate', function() use ($app) {
            global $category;
            global $page;
            $db = new DbHandler();
            $page = $app->request->post('page');
            $category = $app->request->post('categoryid');
            $response = array();
            
            
            $limit = 10;
            $offset = (--$page) * $limit;
            
  // fetching all user tasks
            $result = $db->getCategorizedInfographics ($category,$offset);
            $response["error"] = false;
            $response["infographics"] = array();
            // looping through result and preparing tasks array
            while ($infographic = $result->fetch_assoc()) {
                $tmp = array();
                $tmp["id"] = $infographic["id"];
                $tmp["name"] = $infographic["name"];
                $tmp["image_url"] = $infographic["image_url"];
                $tmp["source_name"] = $infographic["source_name"];
                $tmp["type"] = $infographic["type"];
                $tmp["type_icon_url"] = $infographic["type_icon_url"];
                $tmp["like_counter"] = $infographic["like_counter"];    
                
                
                
                array_push($response["infographics"], $tmp);

            }

            echoRespnse(200, $response);
        });        
        
        
        $app->post('/follwedinfographics','authenticate', function() use ($app) {
            global $user_id;
            global $page;
            $db = new DbHandler();
            $page = $app->request->post('page');
            $user_id = $app->request->post('userid');
            $response = array();
            
            
            $limit = 3;
            $offset = (--$page) * $limit;
            
  // fetching all user tasks
            $result = $db->getfollwedInfographics ($user_id,$offset);
            $response["error"] = false;
            $response["infographics"] = array();
            // looping through result and preparing tasks array
            while ($infographic = $result->fetch_assoc()) {
                $tmp = array();
                $tmp["id"] = $infographic["id"];
                $tmp["name"] = $infographic["name"];
                $tmp["image_url"] = $infographic["image_url"];
                $tmp["source_name"] = $infographic["source_name"];
                $tmp["type"] = $infographic["type"];
                $tmp["type_icon_url"] = $infographic["type_icon_url"];
                $tmp["like_counter"] = $infographic["like_counter"];                
               
                
                array_push($response["infographics"], $tmp);

            }

            echoRespnse(200, $response);
        });


        $app->post('/selectedtag','authenticate', function() use ($app) {
            global $tag_id;
            global $page;
            $db = new DbHandler();
            $page = $app->request->post('page');
            $tag_id = $app->request->post('tagid');
            $response = array();
            
            
            $limit = 10;
            $offset = (--$page) * $limit;
            
  // fetching all user tasks
            $result = $db->getSelectedTag ($tag_id,$offset);
            $response["error"] = false;
            $response["infographics"] = array();
            // looping through result and preparing tasks array
            while ($infographic = $result->fetch_assoc()) {
                $tmp = array();
                $tmp["id"] = $infographic["id"];
                $tmp["name"] = $infographic["name"];
                $tmp["image_url"] = $infographic["image_url"];
                $tmp["source_name"] = $infographic["source_name"];
                $tmp["type"] = $infographic["type"];
                $tmp["type_icon_url"] = $infographic["type_icon_url"];
                $tmp["like_counter"] = $infographic["like_counter"];
               
                
                array_push($response["infographics"], $tmp);

            }

            echoRespnse(200, $response);
        });        
        
        
        $app->post('/bookmarks', 'authenticate', function() use ($app) {
            global $user_id;
            global $page;
            $response = array();
            $db = new DbHandler();
            $page = $app->request->post('page');
            $user_id = $app->request->post('user_id');
            
            $limit = 10;
            $offset = (--$page) * $limit;
            
            // fetching all user tasks
            $result = $db->getUserBookmarks($user_id, $page);

            $response["error"] = false;
            $response["infographics"] = array();

            // looping through result and preparing tasks array
            while ($infographic = $result->fetch_assoc()) {
                $tmp = array();
                $tmp["id"] = $infographic["id"];
                $tmp["name"] = $infographic["name"];
                $tmp["image_url"] = $infographic["image_url"];
                $tmp["source_name"] = $infographic["source_name"];
                $tmp["type"] = $infographic["type"];
                $tmp["type_icon_url"] = $infographic["type_icon_url"];
                $tmp["like_counter"] = $infographic["like_counter"];
                
                array_push($response["infographics"], $tmp);
            }

            echoRespnse(200, $response);
        });
        
        
        $app->post('/search', 'authenticate', function() use ($app) {
            global $search;
            $response = array();
            $search = $app->request->post('search');
            $db = new DbHandler();
            $result = $db->Search($search);
            $response["error"] = false;
            $response["result"] = array();
            
            while ($result_search = $result->fetch_assoc()) {
                $tmp = array();
             
                $tmp["id"] = $result_search["id"];
                $tmp["tag"] = $result_search["tag"];
                $tmp["tag_status"] = $result_search["tag_status"];
                
                array_push($response["result"], $tmp);
            }
            echoRespnse(200, $response);
        });
        
       $app->post('/isbookmarked', 'authenticate', function() use ($app) {
            global $user_id;
            global $infographic_id;
            $response = array();
            $user_id = $app->request->post('user_id');
            $infographic_id = $app->request->post('infographic_id');
            $db = new DbHandler();
            $result = $db->isBookmarked($user_id, $infographic_id);
           
            if ($result != NULL)
            {
                $response["error"] = false;
                if ($result['user_id'] != [])
                {
                    $response["is_bookmarked"] = true;
                    
                }
                else {
                $response["is_bookmarked"] = false;
                }
            }
            
            echoRespnse(200, $response);
        });
        
        
        $app->post('/insertinfographic', 'authenticate', function() use ($app) {
            global $name;
            global $image_url;
            global $source_name;
            global $source_url;
            global $category_id;
            global $source_type_id;
            
            $response = array();
            $name = $app->request->post('name');
            $image_url = $app->request->post('image_url');
            $source_name = $app->request->post('source_name');
            $source_url = $app->request->post('source_url');
            $category_id = $app->request->post('category_id');
            $source_type_id = $app->request->post('source_type_id');
            
            
            $db = new DbHandler();
            $result = $db->insertInfographic($name, $image_url, $source_name,$source_url,$category_id,$source_type_id);
           
            if ($result != NULL)
            {
                $response["error"] = false;
                $response["status"] = "done";
            }
              
            else {
                 $response["error"] = true;
                $response["status"] = "there is some wrong";
            }
            echoRespnse(200, $response);
        });
        
        
        $app->post('/getinfographic', 'authenticate', function() use ($app) {
            global $user_id;
            global $infographic_id;
            $response = array();
            $user_id = $app->request->post('user_id');
            $infographic_id = $app->request->post('infographic_id');
            $db = new DbHandler();
            $result = $db->isBookmarked($user_id, $infographic_id);
           
            $db2 = new DbHandler();
            $result2 = $db2->AH($user_id, $infographic_id);
            
            if ($result != NULL && $result2 != NULL)
            {
                if ($result2['COUNT(id)'] > 0)
                {
                    $AH = true;
                   
                    
                }
                else {
                $AH = false;
                }
                
                if ($result['user_id'] != [])
                {
                    $isBookmarked = true;
                   
                    
                }
                else {
                $isBookmarked = false;
                }
                
                $db2 = new DbHandler();
                $infographic = $db2->getInfographic($infographic_id);
                
                
                if ($infographic != NULL) {
                    $response["error"] = false;
                    $response["isLiked"] = $AH;
                    $response["isBookmarked"] = $isBookmarked;
                    $response["infographic"]['name'] = $infographic['name'];
                    $response["infographic"]['image_url'] = $infographic['image_url'];
                    $response["infographic"]['source_name'] = $infographic['source_name'];
                    $response["infographic"]['source_url'] = $infographic['source_url'];
                    $response["infographic"]['like_counter'] = $infographic['like_counter'];
                    $response["infographic"]['category_id'] = $infographic['category_id'];
                    $response["infographic"]['type'] = $infographic['type'];
                    $response["infographic"]['type_icon_url'] = $infographic['type_icon_url'];
                   
            }
            
              else { 
                $response['error'] = true;
                $response['message'] = 'Faild request';
              }
                
                
                
                
            }
              else {
                $response['error'] = true;
                $response['message'] = 'Faild request';

                 }
            
            echoRespnse(200, $response);
        });
        
        
        $app->get('/tasks', 'authenticate', function() {
            global $user_id;
            $response = array();
            $db = new DbHandler();

            // fetching all user tasks
            $result = $db->getAllUserTasks($user_id);

            $response["error"] = false;
            $response["tasks"] = array();

            // looping through result and preparing tasks array
            while ($task = $result->fetch_assoc()) {
                $tmp = array();
                $tmp["id"] = $task["id"];
                $tmp["task"] = $task["task"];
                $tmp["status"] = $task["status"];
                $tmp["createdAt"] = $task["created_at"];
                array_push($response["tasks"], $tmp);
            }

            echoRespnse(200, $response);
        });
        
        $app->post('/favoriteaction', 'authenticate', function() use ($app){
            global $user_id;
            global $infographic_id;
            $response = array();
            $user_id = $app->request->post('user_id');
            $infographic_id = $app->request->post('infographic_id');
            $db = new DbHandler();
            $result = $db->isliked($user_id, $infographic_id);

            if($result != NULL)
            {
                $response["error"] = false;
               if ($result['user_id'] != [])
                {
                    $isLiked = true;
                    $result2 = $db->MinusFavoriteAction($infographic_id);
                    $response["unliked"] = $result2;
                    $result3 = $db->deleteUserFavorite($user_id, $infographic_id);
                    $response["delete_user_like"]= $result3;
                    
                    
                }
                else {
                $isLiked = false;
                $result2 = $db->plusFavoriteAction($infographic_id);
                $response["liked"] = $result2;
                $result3 = $db->addUserFavorite($user_id, $infographic_id);
                $response["add_user_like"]= $result3;
                } 
            }
              
            else {
                 $response["error"] = true;
            }
            
            

         
            echoRespnse(200, $response);
        });
        

        
        $app->post('/bookmarkaction', 'authenticate', function() use ($app){
            global $user_id;
            global $infographic_id;
            $response = array();
            $user_id = $app->request->post('user_id');
            $infographic_id = $app->request->post('infographic_id');
            $db = new DbHandler();
            $result = $db->isBookmarked($user_id, $infographic_id);

            if($result != NULL)
            {
                $response["error"] = false;
               if ($result['user_id'] != [])
                {
                    $isBookmarked = true;
                    $result2 = $db->deleteUserBookmark($user_id, $infographic_id);
                    $response["delete_user_bookmark"]= $result2;
                    
                    
                }
                else {
                $isBookmarked = false;
               
                $result2 = $db->addUserBookmark($user_id, $infographic_id);
                $response["add_user_bookmark"]= $result2;
                } 
            }
            
            else {
                $response["error"] = true;
            }
            

         
            echoRespnse(200, $response);
        });
        
        
        $app->post('/comment', 'authenticate', function() use ($app){
       
                 verifyRequiredParams(array('infographic_id', 'user_id', 'comment'));

            // reading post params
            $response = array();
            $infographicId = $app->request()->post('infographic_id');
            $userId = $app->request()->post('user_id');
            $comment = $app->request()->post('comment');
            
            
            $db = new DbHandler();
            $result = $db->commentAction($infographicId, $userId, $comment);
            
            if ($result != NULL) {
                $response["error"] = false;
                
            } else {
                $response["error"] = true;
                $response["message"] = "حدث خطأ ما الرجاء إعادة المحاولة";
                
            }
            
                echoRespnse(201, $response);
                });

                
                
                $app->post('/getcomments', 'authenticate', function() use ($app) {
            global $infographicid;
            $response = array();
            $infographicid = $app->request->post('infographic_id');
            $db = new DbHandler();
  // fetching all user tasks
            $result = $db->getInfographicComments($infographicid);
            $response["error"] = false;
            $response["comments"] = array();
            // looping through result and preparing tasks array
            while ($comment = $result->fetch_assoc()) {
                $tmp = array();
                $tmp["name"] = $comment["name"];
                $tmp["comment"] = $comment["comment"];
                $tmp["created_at"] = $comment["created_at"];
                
                
                array_push($response["comments"], $tmp);
            }

            echoRespnse(200, $response);
        });
                
                
/**
 * Listing single task of particual user
 * method GET
 * url /tasks/:id
 * Will return 404 if the task doesn't belongs to user
 */
$app->get('/tasks/:id', 'authenticate', function($task_id) {
            global $user_id;
            $response = array();
            $db = new DbHandler();

            // fetch task
            $result = $db->getTask($task_id, $user_id);

            if ($result != NULL) {
                $response["error"] = false;
                $response["id"] = $result["id"];
                $response["task"] = $result["task"];
                $response["status"] = $result["status"];
                $response["createdAt"] = $result["created_at"];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });

/**
 * Creating new task in db
 * method POST
 * params - name
 * url - /tasks/
 */
$app->post('/tasks', 'authenticate', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('task'));

            $response = array();
            $task = $app->request->post('task');

            global $user_id;
            $db = new DbHandler();

            // creating new task
            $task_id = $db->createTask($user_id, $task);

            if ($task_id != NULL) {
                $response["error"] = false;
                $response["message"] = "Task created successfully";
                $response["task_id"] = $task_id;
                echoRespnse(201, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "Failed to create task. Please try again";
                echoRespnse(200, $response);
            }            
        });

/**
 * Updating existing task
 * method PUT
 * params task, status
 * url - /tasks/:id
 */
$app->put('/tasks/:id', 'authenticate', function($task_id) use($app) {
            // check for required params
            verifyRequiredParams(array('task', 'status'));

            global $user_id;            
            $task = $app->request->put('task');
            $status = $app->request->put('status');

            $db = new DbHandler();
            $response = array();

            // updating task
            $result = $db->updateTask($user_id, $task_id, $task, $status);
            if ($result) {
                // task updated successfully
                $response["error"] = false;
                $response["message"] = "Task updated successfully";
            } else {
                // task failed to update
                $response["error"] = true;
                $response["message"] = "Task failed to update. Please try again!";
            }
            echoRespnse(200, $response);
        });

/**
 * Deleting task. Users can delete only their tasks
 * method DELETE
 * url /tasks
 */
$app->delete('/tasks/:id', 'authenticate', function($task_id) use($app) {
            global $user_id;

            $db = new DbHandler();
            $response = array();
            $result = $db->deleteTask($user_id, $task_id);
            if ($result) {
                // task deleted successfully
                $response["error"] = false;
                $response["message"] = "Task deleted succesfully";
            } else {
                // task failed to delete
                $response["error"] = true;
                $response["message"] = "Task failed to delete. Please try again!";
            }
            echoRespnse(200, $response);
        });

/**
 * Verifying required params posted or not
 */
function verifyRequiredParams($required_fields) {
    $error = false;
    $error_fields = "";
    $request_params = array();
    $request_params = $_REQUEST;
    // Handling PUT request params
    if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
        $app = \Slim\Slim::getInstance();
        parse_str($app->request()->getBody(), $request_params);
    }
    foreach ($required_fields as $field) {
        if (!isset($request_params[$field]) || strlen(trim($request_params[$field])) <= 0) {
            $error = true;
            $error_fields .= $field . ', ';
        }
    }

    if ($error) {
        // Required field(s) are missing or empty
        // echo error json and stop the app
        $response = array();
        $app = \Slim\Slim::getInstance();
        $response["error"] = true;
        $response["message"] = 'Required field(s) ' . substr($error_fields, 0, -2) . ' is missing or empty';
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * Validating email address
 */
function validateEmail($email) {
    $app = \Slim\Slim::getInstance();
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response["error"] = true;
        $response["message"] = 'Email address is not valid';
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * Echoing json response to client
 * @param String $status_code Http response code
 * @param Int $response Json response
 */
function echoRespnse($status_code, $response) {
    $app = \Slim\Slim::getInstance();
    // Http response code
    $app->status($status_code);

    // setting response content type to json
    $app->contentType('application/json');

    echo json_encode($response);
}

$app->run();
?>