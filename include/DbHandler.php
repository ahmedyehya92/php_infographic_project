<?php

/**
 * Class to handle all db operations
 * This class will have CRUD methods for database tables
 *
 * @author Ravi Tamada
 * @link URL Tutorial link
 */
class DbHandler {

    private $conn;

    function __construct() {
        require_once dirname(__FILE__) . '/DbConnect.php';
        // opening db connection
        $db = new DbConnect();
        $this->conn = $db->connect();
    }

    /* ------------- `users` table method ------------------ */

    /**
     * Creating new user
     * @param String $name User full name
     * @param String $email User login email id
     * @param String $password User login password
     */
    public function createUser($name, $email, $password) {
        require_once 'PassHash.php';
        $response = array();

        // First check if user already existed in db
        if (!$this->isUserExists($email)) {
            // Generating password hash
            $password_hash = PassHash::hash($password);

            // Generating API key
            $api_key = $this->generateApiKey();

            // insert query
            $stmt = $this->conn->prepare("INSERT INTO users(name, email, password_hash, api_key, status) values(?, ?, ?, ?, 1)");
            $stmt->bind_param("ssss", $name, $email, $password_hash, $api_key);

            $result = $stmt->execute();

            $stmt->close();

            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                // User successfully inserted
                 $stmt = $this->conn->prepare("SELECT * FROM users WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $user = $stmt->get_result()->fetch_assoc();
            $stmt->close();
 
            return $user;
            } else {
                // Failed to create user
                return USER_CREATE_FAILED;
            }
        } else {
            // User with same email already existed in the db
            return USER_ALREADY_EXISTED;
        }

        return $response;
    }

    
    public function insertInfographic($id, $name, $image_url, $source_name,$source_url,$category_id,$source_type_id) {
        
       
            // insert query
        if ($id ==2)
        {
            $stmt = $this->conn->prepare("INSERT INTO infographics (name,image_url,source_name,source_url,category_id,source_type_id, data_entry) VALUES(?,?,?,?,?,?,?)");
            $stmt->bind_param("ssssiii", $name, $image_url, $source_name, $source_url, $category_id, $source_type_id,$id);

            $result = $stmt->execute();

            $stmt->close();
        }
 else {
     $stmt = $this->conn->prepare("INSERT INTO infographics (name,image_url,source_name,source_url,category_id,source_type_id) VALUES(?,?,?,?,?,?)");
            $stmt->bind_param("ssssii", $name, $image_url, $source_name, $source_url, $category_id, $source_type_id);

            $result = $stmt->execute();

            $stmt->close();
 }
            

            
         

        return $result;
    }
    
    /**
     * Checking user login
     * @param String $email User login email id
     * @param String $password User login password
     * @return boolean User login status success/fail
     */
    public function checkLogin($email, $password) {
        // fetching user by email
        $stmt = $this->conn->prepare("SELECT password_hash FROM users WHERE email = ?");

        $stmt->bind_param("s", $email);

        $stmt->execute();

        $stmt->bind_result($password_hash);

        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            // Found user with the email
            // Now verify the password

            $stmt->fetch();

            $stmt->close();

            if (PassHash::check_password($password_hash, $password)) {
                // User password is correct
                return TRUE;
            } else {
                // user password is incorrect
                return FALSE;
            }
        } else {
            $stmt->close();

            // user not existed with the email
            return FALSE;
        }
    }

    /**
     * Checking for duplicate user by email address
     * @param String $email email to check in db
     * @return boolean
     */
    private function isUserExists($email) {
        $stmt = $this->conn->prepare("SELECT id from users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getUserByEmail($email) {
        $stmt = $this->conn->prepare("SELECT id, name, email, api_key, status, created_at FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($id, $name, $email, $api_key, $status, $created_at);
            $stmt->fetch();
            $user = array();
            $user["id"] = $id;
            $user["name"] = $name;
            $user["email"] = $email;
            $user["api_key"] = $api_key;
            $user["status"] = $status;
            $user["created_at"] = $created_at;
            $stmt->close();
            return $user;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user api key
     * @param String $user_id user id primary key in user table
     */
    public function getApiKeyById($user_id) {
        $stmt = $this->conn->prepare("SELECT api_key FROM users WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            // $api_key = $stmt->get_result()->fetch_assoc();
            // TODO
            $stmt->bind_result($api_key);
            $stmt->close();
            return $api_key;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user id by api key
     * @param String $api_key user api key
     */
    public function getUserId($api_key) {
        $stmt = $this->conn->prepare("SELECT id FROM users WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        if ($stmt->execute()) {
            $stmt->bind_result($user_id);
            $stmt->fetch();
            // TODO
            // $user_id = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $user_id;
        } else {
            return NULL;
        }
    }

    /**
     * Validating user api key
     * If the api key is there in db, it is a valid key
     * @param String $api_key user api key
     * @return boolean
     */
    public function isValidApiKey($api_key) {
        $stmt = $this->conn->prepare("SELECT id from users WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /**
     * Generating random Unique MD5 String for user Api key
     */
    private function generateApiKey() {
        return md5(uniqid(rand(), true));
    }

    /* ------------- `tasks` table method ------------------ */

    /**
     * Creating new task
     * @param String $user_id user id to whom task belongs to
     * @param String $task task text
     */
    //-----------------------------------------------------------
     public function getCategories($category) {
        $stmt = $this->conn->prepare("SELECT id, category, icon, follow_counter FROM categories");
        $stmt->execute();
        $categories = $stmt->get_result();
        $stmt->close();
        return $categories;
    }
    //------------------------------------------------------------
    
    public function getFollowingCategories($category) {
        $stmt = $this->conn->prepare("SELECT id, category, FROM categories");
        $stmt->execute();
        $categories = $stmt->get_result();
        $stmt->close();
        return $categories;
    }
    
    
    public function getCategorizedInfographics ($category, $page) {

        $limit = 5;
        $stmt = $this->conn->prepare("SELECT infographics.id, infographics.name, infographics.image_url,infographics.source_name, source_type.type,source_type.type_icon_url, infographics.like_counter  FROM infographics INNER JOIN source_type ON infographics.source_type_id=source_type.id WHERE category_id = ? LIMIT $limit OFFSET ?");
        $stmt->bind_param("ii", $category,$page);
        $stmt->execute();
        $infographics = $stmt->get_result();
        $stmt->close();
        return $infographics;

    }
    
    
    public function getfollwedInfographics ($user_id, $page) {

        $limit = 10;
        $stmt = $this->conn->prepare("SELECT infographics.id, infographics.name, infographics.image_url,infographics.source_name, source_type.type,source_type.type_icon_url, infographics.like_counter FROM infographics INNER JOIN following ON infographics.category_id=following.category_id INNER JOIN source_type ON infographics.source_type_id=source_type.id WHERE following.user_id = ? ORDER BY infographics.id DESC LIMIT $limit OFFSET ?");
        $stmt->bind_param("ii", $user_id,$page);
        $stmt->execute();
        $infographics = $stmt->get_result();
        $stmt->close();
        return $infographics;

    }
    
    public function getSelectedTag ($tag_id, $page) {

        $limit = 10;
        $stmt = $this->conn->prepare("SELECT infographics.id, infographics.name, infographics.image_url,infographics.source_name, source_type.type,source_type.type_icon_url, infographics.like_counter FROM infographics INNER JOIN tags_relation ON infographics.id=tags_relation.infographic_id INNER JOIN source_type ON infographics.source_type_id=source_type.id WHERE tags_relation.tag_id = ? LIMIT $limit OFFSET ?");
        $stmt->bind_param("ii", $tag_id,$page);
        $stmt->execute();
        $infographics = $stmt->get_result();
        $stmt->close();
        return $infographics;

    }
    
    public function getInfographic($infographic_id) {
    $stmt = $this->conn->prepare("SELECT infographics.name, infographics.image_url,infographics.source_name,infographics.source_url, infographics.like_counter,infographics.category_id, source_type.type,source_type.type_icon_url FROM infographics INNER JOIN source_type ON infographics.source_type_id=source_type.id WHERE infographics.id = ?");
        $stmt->bind_param("s", $infographic_id);
        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($name, $image_url, $source_name, $source_url, $like_counter, $category_id, $type, $type_icon);
            $stmt->fetch();
            $infographic = array();
            $infographic["name"] = $name;
            $infographic["image_url"] = $image_url;
            $infographic["source_name"] = $source_name;
            $infographic["source_url"] = $source_url;
            $infographic["like_counter"] = $like_counter;
            $infographic["category_id"] = $category_id;
            $infographic["type"] = $type;
            $infographic["type_icon_url"] = $type_icon;
    
            $stmt->close();
            return $infographic;
        } else {
            return NULL;
        }
    }
    public function getUserBookmarks($user_id, $page) {
        $limit = 10;
        $stmt = $this->conn->prepare("SELECT infographics.id, infographics.name, infographics.image_url,infographics.source_name, source_type.type,source_type.type_icon_url, infographics.like_counter FROM infographics INNER JOIN user_bookmarks ON infographics.id=user_bookmarks.infographic_id INNER JOIN source_type ON infographics.source_type_id=source_type.id WHERE user_bookmarks.user_id = ? ORDER BY user_bookmarks.id DESC LIMIT $limit OFFSET ?");
        $stmt->bind_param("ii", $user_id, $page);
        $stmt->execute();
        $infographics = $stmt->get_result();
        $stmt->close();
        return $infographics;
    }
    
    
    public function  isBookmarked ($user_id, $infographic_id)
    {
                $stmt = $this->conn->prepare("SELECT user_bookmarks.user_id FROM user_bookmarks WHERE user_bookmarks.user_id = ? AND user_bookmarks.infographic_id = ?");
                $stmt->bind_param("ii", $user_id, $infographic_id);
                if ($stmt->execute()) 
                {
                    
                    $stmt->bind_result($userid);
            $stmt->fetch();
            $isBookmarked = array();
            $isBookmarked["user_id"] = $userid;
           
                   $stmt->close();
                   return $isBookmarked;
                }
                else {
            return NULL;
        }
                
                
    }
    
    

    public function AH($user_id, $infographic_id)
    {
         $stmt2 = $this->conn->prepare("SELECT COUNT(id) FROM user_favortes WHERE user_id = ? AND infographic_id = ?");
                $stmt2->bind_param("ii", $user_id, $infographic_id);
                if ($stmt2->execute()) 
                {
                    
                    $stmt2->bind_result($userid);
            $stmt2->fetch();
            $isBookmarked = array();
            $isBookmarked["COUNT(id)"] = $userid;
           
                   $stmt2->close();
                   return $isBookmarked;
                }
                else {
            return NULL;
        }
                
    }
    
     public function isThereFollowed($user_id)
    {
         $stmt2 = $this->conn->prepare("SELECT COUNT(id) FROM following WHERE user_id = ?");
                $stmt2->bind_param("i", $user_id);
                if ($stmt2->execute()) 
                {
                    
                    $stmt2->bind_result($numberOfFollwed);
            $stmt2->fetch();
            $followed = array();
            $followed["COUNT(id)"] = $numberOfFollwed;
           
                   $stmt2->close();
                   return $followed;
                }
                else {
            return NULL;
        }
                
    }

        public function  isliked ($user_id, $infographic_id)
            
    {
        
        
        
                
                
                $stmt = $this->conn->prepare("SELECT user_favortes.user_id FROM user_favortes WHERE user_favortes.user_id = ? AND user_favortes.infographic_id = ?");
                $stmt->bind_param("ii", $user_id, $infographic_id);
                if ($stmt->execute()) 
                {
                    
                    $stmt->bind_result($userid);
            $stmt->fetch();
            $isBookmarked = array();
            $isBookmarked["user_id"] = $userid;
           
                   $stmt->close();
                   return $isBookmarked;
                }
                else {
            return NULL;
        }
                
                
    }
    
    
    public function  isFollowed ($user_id, $category_id)
    {
                $stmt = $this->conn->prepare("SELECT following.user_id FROM following WHERE following.user_id = ? AND following.category_id = ?");
                $stmt->bind_param("ii", $user_id, $category_id);
                if ($stmt->execute()) 
                {
                    
                    $stmt->bind_result($userid);
            $stmt->fetch();
            $isFollwed = array();
            $isFollwed["user_id"] = $userid;
           
                   $stmt->close();
                   return $isFollwed;
                }
                else {
            return NULL;
        }
                
                
    }

    public function Search ($search)
    {
              
               $stmt = $this->conn->prepare("SELECT * FROM tags WHERE tags.tag LIKE ? UNION SELECT infographics.id, infographics.name, infographics.infographic_status FROM infographics WHERE infographics.name LIKE ?"); 
               $param = "%" . $search . "%"; 
               $stmt->bind_param("ss", $param,$param);
               $stmt->execute();
               $result = $stmt->get_result();
               $stmt->close();
               return $result;
    }
    
    
    public function getInfographicComments($infographicid) {
        $stmt = $this->conn->prepare("SELECT users.name, comments.comment, comments.created_at FROM comments INNER JOIN users ON comments.user_id=users.id WHERE comments.infographic_id = ?");
        $stmt->bind_param("i", $infographicid);
        $stmt->execute();
        $comments = $stmt->get_result();
        $stmt->close();
        return $comments;
        
    }
    
    
    public function plusFavoriteAction($id) {
            
            $stmtp = $this->conn->prepare("UPDATE infographics SET like_counter = like_counter+1 WHERE id = ?");
            $stmtp->bind_param("s", $id);

            $result = $stmtp->execute();

            $stmtp->close();
            if ($result) {
                
                return "done";
            } else {
                
                return NULL;
            }
    }
    
    public function plusFollowAction($id) {
            
            $stmtp = $this->conn->prepare("UPDATE categories SET follow_counter = follow_counter+1 WHERE id = ?");
            $stmtp->bind_param("s", $id);

            $result = $stmtp->execute();

            $stmtp->close();
            if ($result) {
                
                return "done";
            } else {
                
                return NULL;
            }
    }
    public function MinusFollowAction($id) {
            
            $stmtp = $this->conn->prepare("UPDATE categories SET follow_counter = follow_counter-1 WHERE id = ?");
            $stmtp->bind_param("s", $id);

            $result = $stmtp->execute();

            $stmtp->close();
            if ($result) {
                
                return "done";
            } else {
                
                return NULL;
            }
    }
     public function MinusFavoriteAction($id) {
            
            $stmtp = $this->conn->prepare("UPDATE infographics SET like_counter = like_counter-1 WHERE id = ?");
            $stmtp->bind_param("s", $id);

            $result = $stmtp->execute();

            $stmtp->close();
            if ($result) {
                
                return "done";
            } else {
                
                return NULL;
            }
    }
    
    public function addUserFavorite($user_id, $infographic_id) {
            
            $stmtp = $this->conn->prepare("INSERT INTO user_favortes (user_id,infographic_id) VALUES (?,?)");
            $stmtp->bind_param("ii", $user_id, $infographic_id);

            $result = $stmtp->execute();

            $stmtp->close();
            if ($result) {
                
                return "done";
            } else {
                
                return NULL;
            }
    }
    
     public function addUserFollow($user_id, $category_id) {
            
            $stmtp = $this->conn->prepare("INSERT INTO following (user_id,category_id) VALUES (?,?)");
            $stmtp->bind_param("ii", $user_id, $category_id);

            $result = $stmtp->execute();

            $stmtp->close();
            if ($result) {
                
                return "done";
            } else {
                
                return NULL;
            }
    }
    
    
    public function deleteUserFollow($user_id, $category_id) {
            
            $stmtp = $this->conn->prepare("DELETE FROM following WHERE user_id=? AND category_id=?");
            $stmtp->bind_param("ii", $user_id, $category_id);

            $result = $stmtp->execute();

            $stmtp->close();
            if ($result) {
                
                return "done";
            } else {
                
                return NULL;
            }
    }
    
     public function deleteUserFavorite($user_id, $infographic_id) {
            
            $stmtp = $this->conn->prepare("DELETE FROM user_favortes WHERE user_id=? AND infographic_id=?");
            $stmtp->bind_param("ii", $user_id, $infographic_id);

            $result = $stmtp->execute();

            $stmtp->close();
            if ($result) {
                
                return "done";
            } else {
                
                return NULL;
            }
    }
    
    
     public function addUserBookmark($user_id, $infographic_id) {
            
            $stmtp = $this->conn->prepare("INSERT INTO user_bookmarks (user_id,infographic_id) VALUES (?,?)");
            $stmtp->bind_param("ii", $user_id, $infographic_id);

            $result = $stmtp->execute();

            $stmtp->close();
            if ($result) {
                
                return "done";
            } else {
                
                return NULL;
            }
    }
    
    
    public function deleteUserBookmark($user_id, $infographic_id) {
            
            $stmtp = $this->conn->prepare("DELETE FROM user_bookmarks WHERE user_id=? AND infographic_id=?");
            $stmtp->bind_param("ii", $user_id, $infographic_id);

            $result = $stmtp->execute();

            $stmtp->close();
            if ($result) {
                
                return "done";
            } else {
                
                return NULL;
            }
    }
    
    public function commentAction($infographicId, $userId, $comment) {
        $stmt = $this->conn->prepare("INSERT INTO comments (infographic_id, user_id, comment)VALUES (?,?,?)");
        $stmt->bind_param("iis", $infographicId, $userId, $comment);
        $result = $stmt->execute();
        $stmt->close();

        if ($result) {
                
                return "done";
            } else {
                
                return NULL;
            }
    }
    
    
    public function createTask($user_id, $task) {
        $stmt = $this->conn->prepare("INSERT INTO tasks(task) VALUES(?)");
        $stmt->bind_param("s", $task);
        $result = $stmt->execute();
        $stmt->close();

        if ($result) {
            // task row created
            // now assign the task to user
            $new_task_id = $this->conn->insert_id;
            $res = $this->createUserTask($user_id, $new_task_id);
            if ($res) {
                // task created successfully
                return $new_task_id;
            } else {
                // task failed to create
                return NULL;
            }
        } else {
            // task failed to create
            return NULL;
        }
    }

    /**
     * Fetching single task
     * @param String $task_id id of the task
     */
    public function getTask($task_id, $user_id) {
        $stmt = $this->conn->prepare("SELECT t.id, t.task, t.status, t.created_at from tasks t, user_tasks ut WHERE t.id = ? AND ut.task_id = t.id AND ut.user_id = ?");
        $stmt->bind_param("ii", $task_id, $user_id);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($id, $task, $status, $created_at);
            // TODO
            // $task = $stmt->get_result()->fetch_assoc();
            $stmt->fetch();
            $res["id"] = $id;
            $res["task"] = $task;
            $res["status"] = $status;
            $res["created_at"] = $created_at;
            $stmt->close();
            return $res;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching all user tasks
     * @param String $user_id id of the user
     */
    public function getAllUserTasks($user_id) {
        $stmt = $this->conn->prepare("SELECT t.* FROM tasks t, user_tasks ut WHERE t.id = ut.task_id AND ut.user_id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $tasks = $stmt->get_result();
        $stmt->close();
        return $tasks;
    }

    /**
     * Updating task
     * @param String $task_id id of the task
     * @param String $task task text
     * @param String $status task status
     */
    public function updateTask($user_id, $task_id, $task, $status) {
        $stmt = $this->conn->prepare("UPDATE tasks t, user_tasks ut set t.task = ?, t.status = ? WHERE t.id = ? AND t.id = ut.task_id AND ut.user_id = ?");
        $stmt->bind_param("siii", $task, $status, $task_id, $user_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    /**
     * Deleting a task
     * @param String $task_id id of the task to delete
     */
    public function deleteTask($user_id, $task_id) {
        $stmt = $this->conn->prepare("DELETE t FROM tasks t, user_tasks ut WHERE t.id = ? AND ut.task_id = t.id AND ut.user_id = ?");
        $stmt->bind_param("ii", $task_id, $user_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    /* ------------- `user_tasks` table method ------------------ */

    /**
     * Function to assign a task to user
     * @param String $user_id id of the user
     * @param String $task_id id of the task
     */
    public function createUserTask($user_id, $task_id) {
        $stmt = $this->conn->prepare("INSERT INTO user_tasks(user_id, task_id) values(?, ?)");
        $stmt->bind_param("ii", $user_id, $task_id);
        $result = $stmt->execute();

        if (false === $result) {
            die('execute() failed: ' . htmlspecialchars($stmt->error));
        }
        $stmt->close();
        return $result;
    }


}

?>
