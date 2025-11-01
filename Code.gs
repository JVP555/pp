// ---------------------- CONFIG ----------------------
var SPREADSHEET_ID = "1kaoT7oeooYwnrbYO3ohyfz77IBYF3AE611hV98UYSHs";
var MASTER_SHEET_NAME = "MasterData", AUTH_SHEET_NAME = "Authorisation", FORMS_CONFIG_SHEET = "FormsConfig", AUDIT_LOG_SHEET = "AuditLog", ADMIN_ROLES_SHEET = "AdminRoles", STUDENT_PROFILE_CONFIG_SHEET = "StudentProfileConfig";
var ROOT_DRIVE_FOLDER_NAME = "PlacementAppUploads";
var SESSION_DURATION_MS = 60 * 60 * 1000; // 1 hour
var MAX_FILE_SIZE_MB = 10;
var PORTAL_EMAIL_NAME = "CSE PLACEMENT REP";
var RESPONSES_SPREADSHEET_ID = "1bGdK7VFYVeCKCMhbhbwyddnIsIgwjXSNASX-Jp3atZk";

// ---------------------- NEW SESSION TOKEN FUNCTIONS ----------------------

// Generate session token and store it
function authenticateAndGetToken(rollNo, password) {
  try {
    // Use existing authentication logic
    var auth = authenticateStudent_(rollNo, password);
    if (!auth.ok) {
      return { success: false, error: auth.error };
    }
    
    // Generate session token
    var sessionToken = Utilities.getUuid();
    var expiry = new Date(Date.now() + SESSION_DURATION_MS).getTime();
    
    // Store token in PropertiesService
    var tokenData = {
      token: sessionToken,
      expiry: expiry,
      rollNo: rollNo,
      rowID: auth.rowID
    };
    
    PropertiesService.getScriptProperties().setProperty(
      'session_' + rollNo, 
      JSON.stringify(tokenData)
    );
    
    return {
      success: true,
      sessionToken: sessionToken,
      expiry: expiry,
      rowID: auth.rowID
    };
    
  } catch (error) {
    return { success: false, error: "Authentication failed: " + error.message };
  }
}

// Validate session token
function validateSessionToken(rollNo, sessionToken) {
  try {
    var stored = PropertiesService.getScriptProperties().getProperty('session_' + rollNo);
    if (!stored) return false;
    
    var tokenData = JSON.parse(stored);
    
    // Check if token matches and hasn't expired
    if (tokenData.token === sessionToken && Date.now() < tokenData.expiry) {
      // Extend session by 1 hour on valid use
      tokenData.expiry = new Date(Date.now() + SESSION_DURATION_MS).getTime();
      PropertiesService.getScriptProperties().setProperty(
        'session_' + rollNo, 
        JSON.stringify(tokenData)
      );
      return tokenData;
    }
    
    // Token expired or invalid - remove it
    PropertiesService.getScriptProperties().deleteProperty('session_' + rollNo);
    return false;
    
  } catch (error) {
    return false;
  }
}

// Invalidate session token (for logout)
function invalidateSessionToken(rollNo) {
  try {
    PropertiesService.getScriptProperties().deleteProperty('session_' + rollNo);
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// Token-based versions of existing functions
function getStudentFormsStatusWithToken(rollNo, sessionToken) {
  var tokenData = validateSessionToken(rollNo, sessionToken);
  if (!tokenData) {
    return { error: "Session expired. Please sign in again." };
  }
  
  // Call existing function with fake password since we have validated token
  return getStudentFormsStatus(rollNo, "VALIDATED_BY_TOKEN");
}

function getStudentFormConfigSecureWithToken(rollNo, sessionToken, formName) {
  var tokenData = validateSessionToken(rollNo, sessionToken);
  if (!tokenData) {
    return { error: "Session expired. Please sign in again." };
  }
  
  return getStudentFormConfigSecure(rollNo, "VALIDATED_BY_TOKEN", formName);
}

function getStudentDataSecureWithToken(rollNo, sessionToken) {
  var tokenData = validateSessionToken(rollNo, sessionToken);
  if (!tokenData) {
    return { error: "Session expired. Please sign in again." };
  }
  
  return getStudentDataSecure(rollNo, "VALIDATED_BY_TOKEN");
}

function submitOrUpdateResponseWithToken(rollNo, sessionToken, formData, formName) {
  var tokenData = validateSessionToken(rollNo, sessionToken);
  if (!tokenData) {
    return { error: "Session expired. Please sign in again." };
  }
  
  return submitOrUpdateResponse(rollNo, "VALIDATED_BY_TOKEN", formData, formName);
}

function withdrawInterestWithToken(rollNo, sessionToken, formName) {
  var tokenData = validateSessionToken(rollNo, sessionToken);
  if (!tokenData) {
    return { error: "Session expired. Please sign in again." };
  }
  
  return withdrawInterest(rollNo, "VALIDATED_BY_TOKEN", formName);
}

function getStudentProfileDataWithToken(rollNo, sessionToken) {
  var tokenData = validateSessionToken(rollNo, sessionToken);
  if (!tokenData) {
    return { error: "Session expired. Please sign in again." };
  }
  
  return getStudentProfileData(rollNo, "VALIDATED_BY_TOKEN");
}

function updateStudentProfileDirectlyWithToken(rollNo, sessionToken, changes) {
  var tokenData = validateSessionToken(rollNo, sessionToken);
  if (!tokenData) {
    return { error: "Session expired. Please sign in again." };
  }
  
  return updateStudentProfileDirectly(rollNo, "VALIDATED_BY_TOKEN", changes);
}

function changeStudentPasswordWithToken(rollNo, sessionToken, newPassword) {
  var tokenData = validateSessionToken(rollNo, sessionToken);
  if (!tokenData) {
    return { error: "Session expired. Please sign in again." };
  }
  
  // For password changes, we need to validate with current password from token data
  // Since we have a valid token, we can proceed with the password change
  return changeStudentPasswordByToken(rollNo, newPassword, tokenData);
}

// New password change function for token-based authentication
function changeStudentPasswordByToken(rollNo, newPassword, tokenData) {
  try {
    // Validate new password (basic check)
    if (!newPassword || String(newPassword).trim().length < 6) {
      return { success: false, error: "New password must be at least 6 characters long." };
    }

    // Prepare the update data specifically for the password
    var passwordUpdateData = { "Password": newPassword };

    // Call the existing update function, passing the rowID from token
    var updateResult = updateStudentDetails(rollNo, tokenData.rowID, passwordUpdateData);

    // Return result based on the update outcome
    if (updateResult.success) {
      // Check if the success message actually contains 'Password' to be sure
      if (updateResult.message.includes("Password")) {
        logAdminAction_("PASSWORD CHANGE", "Student " + rollNo + " changed their password.", rollNo);
        return { success: true, message: "✅ Password updated successfully!" };
      } else {
        Logger.log("Password change requested for " + rollNo + " but updateStudentDetails reported no change including Password.");
        return { success: false, error: "Password update reported no change." };
      }
    } else {
      logAdminAction_("PASSWORD CHANGE FAIL", "Student " + rollNo + " failed password change: " + updateResult.message, rollNo);
      return { success: false, error: "Password update failed: " + updateResult.message };
    }
  } catch (e) {
    Logger.log("Error in changeStudentPasswordByToken for " + rollNo + ": " + e.stack);
    return { success: false, error: "Server error updating password: " + e.message };
  }
}

// ---------------------- MODIFIED EXISTING FUNCTIONS ----------------------

// Update authenticateStudent_ to bypass password check for token validation
function authenticateStudent_(rollNo, password) {
  if (!rollNo) {
    return { ok: false, error: "rollNo is required." };
  }
  
  // Special bypass for token-validated calls
  if (password === "VALIDATED_BY_TOKEN") {
    // For token-validated calls, we need to get the student data
    try {
      var sheet = getSS().getSheetByName(AUTH_SHEET_NAME);
      if (!sheet || sheet.getDataRange().getNumRows() < 2) {
        return { ok: false, error: "No student authorisation data found!" };
      }
      var data = sheet.getDataRange().getValues();
      var header = data[0].map(h => String(h || '').trim().toLowerCase());
      var rollIdx = header.indexOf("rollno");
      var rowIDIdx = header.indexOf("rowid");

      if (rollIdx === -1 || rowIDIdx === -1) {
        return { ok: false, error: "'rollNo'/'rowID' column missing in Authorisation sheet!" };
      }

      var rn = String(rollNo || '').trim().toUpperCase();
      for (var r = 1; r < data.length; r++) {
        if (String(data[r][rollIdx] || '').trim().toUpperCase() === rn) {
          var masterDataRowID = data[r][rowIDIdx];
          if (!masterDataRowID || isNaN(parseInt(masterDataRowID))) {
            return { ok: false, error: "Student 'rowID' is missing or invalid in Auth sheet. Contact Admin." };
          }

          var studentData = getStudentMasterDataByRowID_(masterDataRowID);
          if (!studentData) {
            return { ok: false, error: "Authentication successful, but your data (Row " + masterDataRowID + ") was not found in MasterData! Contact Admin." };
          }

          return { ok: true, studentData: studentData, rowID: masterDataRowID };
        }
      }
      return { ok: false, error: "Roll number not found!" };
    } catch (e) {
      Logger.log("Error during token bypass authentication: " + e.stack);
      return { ok: false, error: "Server error during authentication. " + e.message };
    }
  }
  
  // Original password-based authentication
  if (!password) {
    return { ok: false, error: "Password is required." };
  }
  
  try {
    var sheet = getSS().getSheetByName(AUTH_SHEET_NAME);
    if (!sheet || sheet.getDataRange().getNumRows() < 2) {
      return { ok: false, error: "No student authorisation data found!" };
    }
    var data = sheet.getDataRange().getValues();
    var header = data[0].map(h => String(h || '').trim().toLowerCase());
    var rollIdx = header.indexOf("rollno");
    var passIdx = header.indexOf("password");
    var rowIDIdx = header.indexOf("rowid");

    if (rollIdx === -1 || passIdx === -1 || rowIDIdx === -1) {
      return { ok: false, error: "'rollNo'/'Password'/'rowID' column missing in Authorisation sheet!" };
    }

    var rn = String(rollNo || '').trim().toUpperCase();
    var pw = String(password || '').trim();
    for (var r = 1; r < data.length; r++) {
      if (String(data[r][rollIdx] || '').trim().toUpperCase() === rn) {
        if (String(data[r][passIdx] || '').trim() !== pw) {
          return { ok: false, error: "Invalid password!" };
        }
        
        var masterDataRowID = data[r][rowIDIdx];
        if (!masterDataRowID || isNaN(parseInt(masterDataRowID))) {
            return { ok: false, error: "Student 'rowID' is missing or invalid in Auth sheet. Contact Admin." };
        }

        var studentData = getStudentMasterDataByRowID_(masterDataRowID);
        if (!studentData) {
          return { ok: false, error: "Authentication successful, but your data (Row " + masterDataRowID + ") was not found in MasterData! Contact Admin." };
        }

        return { ok: true, studentData: studentData, rowID: masterDataRowID }; 
      }
    }
    return { ok: false, error: "Roll number not found!" };
  } catch (e) {
    Logger.log("Error during authenticateStudent_: " + e.stack);
    return { ok: false, error: "Server error during authentication. " + e.message };
  }
}

// ---------------------- CORE HELPERS ----------------------
function getSS() {
  if (!SPREADSHEET_ID || SPREADSHEET_ID === "YOUR_SPREADSHEET_ID_HERE") {
    throw new Error("SPREADSHEET_ID is not set.");
  }
  return SpreadsheetApp.openById(SPREADSHEET_ID);
}
function getResponsesSS() {
  if (!RESPONSES_SPREADSHEET_ID || RESPONSES_SPREADSHEET_ID === "YOUR_NEW_SPREADSHEET_ID_HERE") {
    throw new Error("RESPONSES_SPREADSHEET_ID is not set.");
  }
  return SpreadsheetApp.openById(RESPONSES_SPREADSHEET_ID);
}
function doGet(e) {
  Logger.log("doGet triggered. Parameters: " + JSON.stringify(e.parameter));
  var p = e.parameter.page || '';
  if (p === "admin") {
    return HtmlService.createHtmlOutputFromFile('admin').setTitle('Admin Panel');
  }
  var t = HtmlService.createTemplateFromFile('form');
  t.formNameFromServer = e.parameter.formName || e.parameter.form || "";
  Logger.log("Injecting formNameFromServer: " + t.formNameFromServer);
  return t.evaluate().setTitle('Placement Forms');
}

function logAdminAction_(action, details, actor) {
  try {
    var ss = getSS();
    var sheet = ss.getSheetByName(AUDIT_LOG_SHEET);
    if (!sheet) {
      sheet = ss.insertSheet(AUDIT_LOG_SHEET);
      sheet.appendRow(["Timestamp", "Actor Email", "Action", "Details"]);
    }
    sheet.insertRowAfter(1);
    sheet.getRange(2, 1, 1, 4).setValues([[new Date(), actor || "System", action, details]]);
  } catch (e) {
    console.error("Audit log failed: " + e.message);
    Logger.log("Audit log failed: " + e.stack);
  }
}

// ---------------------- ADMIN AUTH ----------------------

function getAdminRole() {
  try {
    var email = Session.getActiveUser().getEmail();
    if (!email) return "Guest";

    var sheet = getSS().getSheetByName(ADMIN_ROLES_SHEET);
    if (!sheet || sheet.getDataRange().getNumRows() < 2) return "Guest";

    var data = sheet.getDataRange().getValues();
    var header = data[0];
    var emailIdx = header.indexOf("Email");
    var roleIdx = header.indexOf("Role");

    if (emailIdx === -1 || roleIdx === -1) {
      Logger.log("AdminRoles sheet missing Email or Role column.");
      return "Guest";
    }

    for (var i = 1; i < data.length; i++) {
      if (String(data[i][emailIdx] || '').trim().toLowerCase() === email.toLowerCase()) {
        return String(data[i][roleIdx] || '').trim();
      }
    }
  } catch (e) {
    console.error("Error getting admin role:", e);
    Logger.log("Error getting admin role: " + e.stack);
    return "Guest";
  }
  return "Guest";
}

function checkAdminAccess(requiredRole) {
  var roles = { "SuperAdmin": 3, "Editor": 2, "Viewer": 1, "Guest": 0 };
  var userRole = getAdminRole();
  var hasAccess = (roles[userRole] || 0) >= (roles[requiredRole] || 0);
  if (!hasAccess) {
    logAdminAction_("ACCESS DENIED", "Attempted " + requiredRole + " action. Role: " + userRole, Session.getActiveUser().getEmail());
  }
  return hasAccess;
}

function getStudentMasterDataByRowID_(rowID) {
  var sheet = getSS().getSheetByName(MASTER_SHEET_NAME);
  if (!sheet || sheet.getDataRange().getNumRows() < 2) return null;

  try {
    var header = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0].map(function(h) { 
      return String(h || '').trim(); 
    });
    
    // Check if rowID is valid
    if (rowID < 2 || rowID > sheet.getLastRow()) {
        Logger.log("Error in getStudentMasterDataByRowID_: rowID " + rowID + " is out of bounds.");
        return null;
    }

    var dataRow = sheet.getRange(rowID, 1, 1, header.length).getValues()[0];
    
    var obj = {};
    for (var c = 0; c < header.length; c++) {
      if (header[c]) {
        obj[header[c]] = dataRow[c];
      }
    }
    return obj;

  } catch (e) {
    Logger.log("Error in getStudentMasterDataByRowID_ for row " + rowID + ": " + e.stack);
  }
  return null;
}

// ---------------------- STUDENT AUTH & DATA ----------------------

function getStudentDataSecure(rollNo, password) {
  var res = authenticateStudent_(rollNo, password);
  return res.ok ? res.studentData : { error: res.error };
}

function getStudentProfileData(rollNo, password) {
  var auth = authenticateStudent_(rollNo, password);
  if (!auth.ok) { return { error: auth.error }; }

  var profileData = {};
  for (var key in auth.studentData) {
    if (auth.studentData.hasOwnProperty(key)) {
      profileData[key] = auth.studentData[key];
    }
  }

  // Only fetch password if not using token bypass
  if (password !== "VALIDATED_BY_TOKEN") {
    try {
      var sheet = getSS().getSheetByName(AUTH_SHEET_NAME);
      var data = sheet.getDataRange().getValues();
      var header = data[0].map(h => String(h || '').trim().toLowerCase());
      var rollIdx = header.indexOf("rollno");
      var passIdx = header.indexOf("password");
      if (rollIdx === -1 || passIdx === -1) {
        throw new Error("Auth sheet missing rollNo/Password header");
      }

      var rn = String(rollNo || '').trim().toUpperCase();
      var found = false;
      for (var r = 1; r < data.length; r++) {
        if (String(data[r][rollIdx] || '').trim().toUpperCase() === rn) {
          profileData.Password = data[r][passIdx];
          found = true;
          break;
        }
      }
      if (!found) {
        profileData.Password = "";
      }
    } catch (e) {
      Logger.log("Error fetching password in getStudentProfileData: " + e.stack);
      profileData.Password = "[Error fetching password]";
    }
  } else {
    profileData.Password = "••••••••"; // Hidden for token-based access
  }

  return { success: true, data: profileData, editableFields: getEditableFields_() };
}

function updateStudentProfileDirectly(rollNo, password, changes) {
  var auth = authenticateStudent_(rollNo, password);
  if (!auth.ok) {
    return { success: false, message: auth.error };
  }

  var editableFields = getEditableFields_();
  var allowedChanges = {};
  for (var key in changes) {
    if (changes.hasOwnProperty(key) && editableFields.indexOf(key) !== -1) {
      allowedChanges[key] = changes[key];
    }
  }

  if (Object.keys(allowedChanges).length === 0) {
    return { success: true, message: "No changes submitted for editable fields." };
  }

  var updateResult = updateStudentDetails(rollNo, auth.rowID, allowedChanges);

  if (updateResult.success) {
    logAdminAction_("STUDENT PROFILE UPDATE", "Student " + rollNo + " updated " + Object.keys(allowedChanges).join(', '), rollNo);
    return { success: true, message: "✅ Profile updated successfully!" };
  } else {
    logAdminAction_("STUDENT PROFILE FAIL", "Student " + rollNo + " failed update: " + updateResult.message, rollNo);
    return { success: false, message: "Update failed: " + updateResult.message };
  }
}

function changeStudentPassword(rollNo, currentPassword, newPassword) {
  var auth = authenticateStudent_(rollNo, currentPassword);
  if (!auth.ok) {
    return { success: false, message: "Authentication failed. Incorrect current password?" };
  }

  if (!newPassword || String(newPassword).trim().length < 3) {
      return { success: false, message: "New password is too short." };
  }

  var passwordUpdateData = { "Password": newPassword };
  var updateResult = updateStudentDetails(rollNo, auth.rowID, passwordUpdateData);

  if (updateResult.success) {
    if (updateResult.message.includes("Password")) {
       logAdminAction_("PASSWORD CHANGE", "Student " + rollNo + " changed their password.", rollNo);
       return { success: true, message: "✅ Password updated successfully!" };
    } else {
       Logger.log("Password change requested for " + rollNo + " but updateStudentDetails reported no change including Password.");
       return { success: false, message: "Password update reported no change." };
    }
  } else {
    logAdminAction_("PASSWORD CHANGE FAIL", "Student " + rollNo + " failed password change: " + updateResult.message, rollNo);
    return { success: false, message: "Password update failed: " + updateResult.message };
  }
}

function isStudentAllowed_(formConfig, studentrollNo) {
  try {
    var allowedListRaw = formConfig.allowedStudents || "";
    if (!allowedListRaw.trim()) {
      return true;
    }
    var allowedList = allowedListRaw.split(',').map(function(rn) {
      return String(rn || '').trim().toUpperCase();
    });
    var rollNoUpper = String(studentrollNo || '').trim().toUpperCase();
    return allowedList.indexOf(rollNoUpper) !== -1;
  } catch (e) {
    Logger.log("Error in isStudentAllowed_: " + e.stack);
    return false;
  }
}

function getStudentFormsStatus(rollNo, password) {
  var auth = authenticateStudent_(rollNo, password);
  if (!auth.ok) { return { error: auth.error }; }

  if (!auth.rowID || isNaN(parseInt(auth.rowID)) || auth.rowID < 2) {
    return { error: "Your account is missing a valid 'rowID'. Contact Admin." };
  }
  var studentRow = auth.rowID;

  try {
    var forms = listFormsPublic_();
    if (!forms) { return { forms: [] }; }
    var ss = getResponsesSS();

    var result = [];
    for (var i = 0; i < forms.length; i++) {
      var f = forms[i];
      var isAllowed = isStudentAllowed_({ allowedStudents: f.allowedStudents }, rollNo);
      if (!isAllowed) {
        continue;
      }

      var submitted = false;
      var interested = "";

      var responseSheet = ss.getSheetByName(f.responseSheet);
      if (responseSheet && responseSheet.getLastRow() >= studentRow) {
        var rollNoCell = responseSheet.getRange(studentRow, 1).getValue();
        if (String(rollNoCell || "").trim().toUpperCase() === rollNo.toUpperCase()) {
            submitted = true;
            
            var header = responseSheet.getRange(1, 1, 1, responseSheet.getLastColumn()).getValues()[0];
            var interestedIdx = header.indexOf("Interested");
            if (interestedIdx !== -1) {
              interested = responseSheet.getRange(studentRow, interestedIdx + 1).getValue() || "";
            } else {
              interested = "Yes";
            }
        }
      }
      
      result.push({
        formName: f.formName,
        isOpen: f.isOpen,
        deadlineMs: f.deadlineMs || 0,
        submitted: submitted,
        interested: interested,
        url: ScriptApp.getService().getUrl() + "?formName=" + encodeURIComponent(f.formName)
      });
    }

    return { forms: result };
  } catch (e) {
    Logger.log("Error in getStudentFormsStatus: " + e.stack);
    return { error: "Server error loading form statuses." };
  }
}

// ---------------------- GENERIC HELPERS ----------------------

function normalizeFieldsConfig_(fieldsRaw) {
  try {
    var fields = typeof fieldsRaw === 'string' ? JSON.parse(fieldsRaw) : (fieldsRaw || []);
    if (!Array.isArray(fields)) {
      Logger.log("Fields config is not an array: " + fieldsRaw);
      return [];
    }
    var normalized = [];
    for (var i = 0; i < fields.length; i++) {
      var f = fields[i];
      var key = String(f.key || f.name || f.label || '').trim();
      var label = String(f.label || f.name || key).trim();

      if (key && label) {
        normalized.push({
          key: key,
          label: label,
          source: String(f.source || 'custom').trim(),
          type: String(f.type || 'text').trim(),
          options: String(f.options || '').trim()
        });
      }
    }
    return normalized;
  } catch (e) {
    Logger.log("Error parsing/normalizing fields config: " + e.stack + " Input: " + fieldsRaw);
    return [];
  }
}

function ensureFormsConfigSchema_() {
  try {
    var ss = getSS();
    var sheetName = FORMS_CONFIG_SHEET;
    var sheet = ss.getSheetByName(sheetName);
    var expectedHeaders = ["Form ID", "Form Name", "Fields to Show", "Created Date", "Response Sheet", "Accepting", "Deadline", "Description", "File Link", "Allowed Students"];

    if (!sheet) {
      sheet = ss.insertSheet(sheetName);
      sheet.appendRow(expectedHeaders);
      Logger.log("Created FormsConfig sheet with headers.");
      return sheet;
    }

    var lastCol = sheet.getLastColumn();
    if (lastCol === 0) {
      sheet.appendRow(expectedHeaders);
      Logger.log("Added headers to empty FormsConfig sheet.");
      return sheet;
    }

    var header = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
    var missingHeaders = [];
    for (var i = 0; i < expectedHeaders.length; i++) {
      if (header.indexOf(expectedHeaders[i]) === -1) {
        missingHeaders.push(expectedHeaders[i]);
      }
    }

    if (missingHeaders.length > 0) {
      sheet.getRange(1, header.length + 1, 1, missingHeaders.length).setValues([missingHeaders]);
      Logger.log("Added missing headers to FormsConfig: " + missingHeaders.join(', '));
    }

    return sheet;
  } catch (e) {
    Logger.log("Error in ensureFormsConfigSchema_: " + e.stack);
    throw new Error("Could not ensure FormsConfig schema: " + e.message);
  }
}

function ensureStudentProfileConfigSchema_() {
  try {
    var ss = getSS();
    var sheetName = STUDENT_PROFILE_CONFIG_SHEET;
    var sheet = ss.getSheetByName(sheetName);
    var expectedHeaders = ["Field Name", "Is Editable"];

    if (!sheet) {
      sheet = ss.insertSheet(sheetName);
      sheet.appendRow(expectedHeaders);
      Logger.log("Created StudentProfileConfig sheet with headers.");
      return sheet;
    }

    var lastCol = sheet.getLastColumn();
    if (lastCol === 0) {
      sheet.appendRow(expectedHeaders);
      Logger.log("Added headers to empty StudentProfileConfig sheet.");
      return sheet;
    }

    var header = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
    var missingHeaders = [];
    for (var i = 0; i < expectedHeaders.length; i++) {
      if (header.indexOf(expectedHeaders[i]) === -1) {
        missingHeaders.push(expectedHeaders[i]);
      }
    }

    if (missingHeaders.length > 0) {
      sheet.getRange(1, header.length + 1, 1, missingHeaders.length).setValues([missingHeaders]);
      Logger.log("Added missing headers to StudentProfileConfig: " + missingHeaders.join(', '));
    }

    return sheet;
  } catch (e) {
    Logger.log("Error in ensureStudentProfileConfigSchema_: " + e.stack);
    throw new Error("Could not ensure StudentProfileConfig schema: " + e.message);
  }
}

function findRowByValue_(sheet, colIndex, value) {
  if (!sheet) return null;
  try {
    var lastRow = sheet.getLastRow();
    if (lastRow < 2) return null;

    var data = sheet.getRange(1, 1, lastRow, Math.max(sheet.getLastColumn(), colIndex + 1)).getValues();
    var valLower = String(value || '').trim().toLowerCase();
    if (!valLower) return null;

    for (var i = 1; i < data.length; i++) {
      if (data[i].length > colIndex && data[i][colIndex] !== null && data[i][colIndex] !== undefined) {
        if (String(data[i][colIndex]).trim().toLowerCase() === valLower) {
          return { row: i + 1, data: data[i] };
        }
      }
    }
  } catch (e) {
    Logger.log("Error in findRowByValue_: Sheet=" + sheet.getName() + ", ColIndex=" + colIndex + ", Value=" + value + ", Error: " + e.stack);
  }
  return null;
}

function getStudentMasterDataByRoll_(rollNoUpper) {
  var sheet = getSS().getSheetByName(MASTER_SHEET_NAME);
  if (!sheet || sheet.getDataRange().getNumRows() < 2) return null;

  try {
    var data = sheet.getDataRange().getValues();
    var header = data[0].map(function(h) { return String(h || '').trim(); });
    var rollIdx = -1;
    for (var i = 0; i < header.length; i++) {
      if (header[i].toLowerCase() === "rollno") {
        rollIdx = i;
        break;
      }
    }

    if (rollIdx === -1) {
      Logger.log("rollNo column not found in MasterData headers: " + header.join(','));
      return null;
    }

    for (var r = 1; r < data.length; r++) {
      if (String(data[r][rollIdx] || "").trim().toUpperCase() === rollNoUpper) {
        var obj = {};
        for (var c = 0; c < header.length; c++) {
          if (header[c]) {
            obj[header[c]] = data[r][c];
          }
        }
        return obj;
      }
    }
  } catch (e) {
    Logger.log("Error in getStudentMasterDataByRoll_: " + e.stack);
  }
  return null;
}

function getFormConfig(formName) {
  if (!formName) {
    return { error: "Form name is required." };
  }
  try {
    var sheet = ensureFormsConfigSchema_();
    var found = findRowByValue_(sheet, 1, formName);
    if (!found) {
      return { error: "Form not found: '" + formName + "'" };
    }

    var lastCol = sheet.getLastColumn();
    var header = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
    var row = found.data;

    var acceptingIdx = header.indexOf("Accepting");
    var deadlineIdx = header.indexOf("Deadline");
    var fieldsIdx = header.indexOf("Fields to Show");
    var responseSheetIdx = header.indexOf("Response Sheet");
    var descIdx = header.indexOf("Description");
    var fileLinkIdx = header.indexOf("File Link");
    var allowedIdx = header.indexOf("Allowed Students");

    if (acceptingIdx === -1 || deadlineIdx === -1 || fieldsIdx === -1 || responseSheetIdx === -1 || allowedIdx === -1) {
      Logger.log("FormsConfig sheet is missing required headers. Found: " + header.join(', '));
      return { error: "Server configuration error: FormsConfig sheet headers invalid." };
    }

    var manualAccepting = row[acceptingIdx] !== false;
    var deadlineVal = row[deadlineIdx];
    var deadlineMs = deadlineVal instanceof Date ? deadlineVal.getTime() : 0;
    var fields = normalizeFieldsConfig_(row[fieldsIdx]);

    return {
      formName: row[1],
      fields: fields,
      responseSheet: row[responseSheetIdx],
      accepting: manualAccepting,
      isOpen: manualAccepting && (!deadlineMs || Date.now() < deadlineMs),
      deadlineMs: deadlineMs,
      description: row[descIdx] || "",
      fileLink: row[fileLinkIdx] || "",
      allowedStudents: row[allowedIdx] || ""
    };
  } catch (e) {
    Logger.log("Error in getFormConfig for '" + formName + "': " + e.stack);
    return { error: "Server error getting form configuration." };
  }
}


function getStudentResponseByRow(formName, rowID) {
  Logger.log('getStudentResponseByRow: Called with formName=' + formName + ', rowID=' + rowID);
  if (!formName || !rowID || isNaN(parseInt(rowID)) || rowID < 2) {
    Logger.log('getStudentResponseByRow: FAILED validation. Returning error.');
    return { exists: false, error: "Invalid form name or rowID." };
  }
  try {
    var cfg = getFormConfig(formName);
    Logger.log('getStudentResponseByRow: Config object: ' + JSON.stringify(cfg));
    if (cfg.error) {
      return { exists: false, error: cfg.error };
    }
    if (!cfg.responseSheet) {
      return { exists: false };
    }

    var ss = getResponsesSS();
    var sheet = ss.getSheetByName(cfg.responseSheet);
    if (!sheet || sheet.getLastRow() < rowID) {
      return { exists: false };
    }

    var lastCol = sheet.getLastColumn();
    if (lastCol === 0 || sheet.getLastRow() < 1) {
       return { exists: false, error: "Response sheet is empty or has no header." };
    }
    
    var header = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
    var dataRow = sheet.getRange(rowID, 1, 1, lastCol).getValues()[0];
    
    if (!dataRow[0] || String(dataRow[0]).trim() === "") {
        return { exists: false };
    }

    var obj = {};
    for (var c = 0; c < header.length; c++) {
      if (header[c]) {
        obj[header[c]] = dataRow[c];
      }
    }
    
    return { exists: true, data: obj };

  } catch (e) {
    Logger.log("Error in getStudentResponseByRow for '" + formName + "', row '" + rowID + "': " + e.stack);
    return { exists: false, error: "Server error checking existing response." };
  }
}

function getStudentFormConfigSecure(rollNo, password, formName) {
  var auth = authenticateStudent_(rollNo, password);
  if (!auth.ok) {
    return { error: auth.error };
  }

  var cfg = getFormConfig(formName);
  if (cfg.error) {
    return cfg;
  }

  if (!isStudentAllowed_(cfg, auth.studentData.rollNo)) {
    Logger.log("Access denied via getStudentFormConfigSecure for " + auth.studentData.rollNo + " to form " + formName);
    return { error: "You are not authorized to view this specific form." };
  }

  return cfg;
}

// ---------------------- STUDENT-FACING ACTIONS ----------------------
function getDriveFolder_() {
  var parentFolder = DriveApp.getRootFolder();
  var folder;
  for (var i = 0; i < arguments.length; i++) {
    var name = arguments[i];
    if (!name) {
      console.warn("Skipping empty folder name in path.");
      continue;
    }
    var folders = parentFolder.getFoldersByName(name);
    folder = folders.hasNext() ? folders.next() : parentFolder.createFolder(name);
    parentFolder = folder;
  }
  return folder;
}

function uploadFileToDrive_(formName, rollNo, fileData) {
  try {
    var base64 = fileData.base64;
    var type = fileData.type;
    var name = fileData.name;

    if (!base64 || !type || !name) {
      Logger.log("File data incomplete for upload: " + JSON.stringify(fileData));
      return "Upload Failed: File data incomplete";
    }

    // Validate file size
    var base64Data = base64.split(",")[1] || base64;
    var sizeInBytes = (base64Data.length * 3) / 4;
    var sizeInMB = sizeInBytes / (1024 * 1024);
    if (sizeInMB > MAX_FILE_SIZE_MB) {
      return "Upload Failed: File size exceeds " + MAX_FILE_SIZE_MB + "MB limit";
    }

    // Validate MIME type (basic check)
    var allowedTypes = ['image/', 'application/pdf', 'application/msword', 'application/vnd.', 'text/'];
    var isAllowedType = false;
    for (var i = 0; i < allowedTypes.length; i++) {
      if (type.indexOf(allowedTypes[i]) === 0) {
        isAllowedType = true;
        break;
      }
    }
    if (!isAllowedType) {
      return "Upload Failed: File type not allowed";
    }

    var safeName = name.replace(/[^a-zA-Z0-9._-]/g, '_');
    var finalName = rollNo + "_" + safeName;

    var decodedBytes = Utilities.base64Decode(base64Data);
    var blob = Utilities.newBlob(decodedBytes, type, finalName);

    var safeFormName = formName.replace(/\W/g, '_');
    var folder = getDriveFolder_(ROOT_DRIVE_FOLDER_NAME, safeFormName);

    var oldFiles = folder.getFilesByName(finalName);
    while (oldFiles.hasNext()) {
      oldFiles.next().setTrashed(true);
    }

    var file = folder.createFile(blob);

    try {
      var userEmail = Session.getActiveUser().getEmail();
      if (userEmail) {
        file.setOwner(userEmail);
      }
    } catch (ownerError) {
      console.warn("Could not set file owner: " + ownerError.message);
      Logger.log("Could not set file owner for file " + finalName + ": " + ownerError.stack);
    }
    return file.getUrl();
  } catch (e) {
    console.error("File upload failed for " + rollNo + " in " + formName + ": " + e.message);
    Logger.log("File upload failed for " + rollNo + " in " + formName + ": " + e.stack);
    return "Upload Failed: " + e.message;
  }
}


function submitOrUpdateResponse(rollNo, password, formData, formName) {
  var auth = authenticateStudent_(rollNo, password);
  if (!auth.ok) { return { success: false, message: auth.error }; }

  if (!auth.rowID || isNaN(parseInt(auth.rowID)) || auth.rowID < 2) {
    return { success: false, message: "⛔ Your account is missing a valid 'rowID'. Contact Admin." };
  }
  var studentRow = auth.rowID;

  var cfg = getFormConfig(formName);
  if (cfg.error) { return { success: false, message: "⛔ Form Error: " + cfg.error }; }
  if (!cfg.isOpen) { return { success: false, message: "⛔ Form is closed." }; }

  if (!isStudentAllowed_(cfg, auth.studentData.rollNo)) {
    return { success: false, message: "⛔ You are not authorized to submit to this form." };
  }

  try {
    var ss = getResponsesSS();
    var sheet = ss.getSheetByName(cfg.responseSheet);
    if (!sheet) {
      sheet = ss.insertSheet(cfg.responseSheet);
      Logger.log("Created response sheet: " + cfg.responseSheet);
    }
    var headerRow = ensureResponseSheetHeader_(sheet, cfg.fields || []);
    if (!headerRow || headerRow.length === 0) {
      throw new Error("Could not ensure header row for " + cfg.responseSheet);
    }

    var customMap = {};
    for (var key in formData) {
      if (formData.hasOwnProperty(key) && key !== "rollNo") {
        var value = formData[key];
        if (typeof value === 'object' && value !== null && value.base64 && value.type && value.name) {
          Logger.log("Uploading file for key: " + key);
          var fileUrl = uploadFileToDrive_(formName, rollNo, value);
          if (String(fileUrl).indexOf("Upload Failed:") === 0) {
            Logger.log("File upload failed for " + rollNo + ", key " + key + ": " + fileUrl);
            return { success: false, message: "⛔ " + fileUrl };
          }
          customMap[key] = fileUrl;
        } else if (value !== undefined) {
          customMap[key] = value;
        }
      }
    }

    var row = buildResponseRow_(headerRow, cfg.fields, auth.studentData, customMap, rollNo, "Yes", null);

    var message = "";
    
    if (headerRow.length > 0) {
      sheet.getRange(studentRow, 1, 1, headerRow.length).setValues([row]);
      message = "✅ Interest submitted successfully!";
      Logger.log("Wrote response for " + rollNo + " to " + formName + " at row " + studentRow);
    } else {
      throw new Error("Invalid header row length before write.");
    }

    try {
      var studentEmail = auth.studentData["College Email ID"]; 
      
      if (studentEmail && String(studentEmail).indexOf('@') !== -1) {
        var subject = "Confirmation: Your Submission for " + formName;
        var body = "Hi " + (auth.studentData.Name || rollNo) + ",\n\n" +
                   "Your response for the form \"" + formName + "\" has been recorded successfully.\n\n" +
                   "--- Your Submission ---\n";
        
        for (var i = 0; i < headerRow.length; i++) {
          var val = row[i];
          if (val) { 
            var displayVal = String(val instanceof Date ? val.toLocaleString() : val);
            if (displayVal.startsWith("http")) {
              // Don't truncate links
            } else if (displayVal.length > 200) {
              displayVal = displayVal.substring(0, 200) + "...";
            }
            body += headerRow[i] + ": " + displayVal + "\n";
          }
        }
        
        body += "\nThank you,\nPlacement Portal";

        MailApp.sendEmail(studentEmail, subject, body, {
          name: PORTAL_EMAIL_NAME,
        });
        Logger.log("Sent submission email to " + studentEmail + " for " + formName);

      } else {
        Logger.log("Could not send submission email: Student email not found or invalid for " + rollNo);
        message += " (No valid email found)";
      }
    } catch (e) {
      console.error("Failed to send confirmation email to " + studentEmail + " for " + formName + ": " + e.message);
      Logger.log("Failed confirmation email to " + studentEmail + " for " + formName + ": " + e.stack);
      message += " (Could not send confirmation email)";
    }

    return { success: true, message: message };

  } catch (e) {
    Logger.log("Error in submitOrUpdateResponse for " + rollNo + ", form " + formName + ": " + e.stack);
    return { success: false, message: "⛔ Server error submitting response: " + e.message };
  }
}

function withdrawInterest(rollNo, password, formName) {
  var auth = authenticateStudent_(rollNo, password);
  if (!auth.ok) {
    return { success: false, message: auth.error };
  }

  if (!auth.rowID || isNaN(parseInt(auth.rowID)) || auth.rowID < 2) {
    return { success: false, message: "⛔ Your account is missing a valid 'rowID'. Contact Admin." };
  }
  var studentRow = auth.rowID;

  var cfg = getFormConfig(formName);
  if (cfg.error || !cfg.isOpen) {
    return { success: false, message: "⛔ Form is closed or invalid." };
  }

  if (!isStudentAllowed_(cfg, auth.studentData.rollNo)) {
    return { success: false, message: "⛔ You are not authorized for this form." };
  }

  try {
    var ss = getResponsesSS();
    var sheet = ss.getSheetByName(cfg.responseSheet);
    if (!sheet) {
      return { success: false, message: "❌ No submission found to withdraw." };
    }

    var headerRow = ensureResponseSheetHeader_(sheet, cfg.fields || []);
    if (!headerRow || headerRow.length === 0) {
      throw new Error("Could not ensure header row for " + cfg.responseSheet);
    }

    sheet.getRange(studentRow, 1, 1, headerRow.length).clearContent();

    var message = "✅ Submission withdrawn.";

    try {
      var studentEmail = auth.studentData["College Email ID"];
      if (studentEmail && String(studentEmail).indexOf('@') !== -1) {
        var subject = "Withdrawal Confirmation: " + formName;
        var body =
          "Hi " + (auth.studentData.Name || rollNo) + ",\n\n" +
          "This email confirms that your submission for the form \"" + formName + "\" has been withdrawn and deleted.\n\n" +
          "Thank you,\nPlacement Portal";

        MailApp.sendEmail(studentEmail, subject, body, {
          name: PORTAL_EMAIL_NAME,
        });
        Logger.log("Sent withdrawal email to " + studentEmail + " for " + formName);
      } else {
        Logger.log("Could not send withdrawal email: Student email not found for " + rollNo);
        message += " (No valid email found)";
      }
    } catch (e) {
      console.error("Failed to send withdrawal email to " + studentEmail + " for " + formName + ": " + e.message);
      Logger.log("Failed withdrawal email to " + studentEmail + " for " + formName + ": " + e.stack);
      message += " (Could not send confirmation email)";
    }

    Logger.log("Cleared submission row for " + rollNo + " from " + formName + " at row " + studentRow);
    return { success: true, message: message };

  } catch (e) {
    Logger.log("Error in withdrawInterest for " + rollNo + ", form " + formName + ": " + e.stack);
    return { success: false, message: "⛔ Server error withdrawing interest: " + e.message };
  }
}

function sendPasswordReminder(rollNo) {
  if (!rollNo) { return { success: false, message: "rollNo is required." }; }
  var rollNoUpper = String(rollNo).trim().toUpperCase();
  try {
    var masterSheet = getSS().getSheetByName(MASTER_SHEET_NAME);
    if (!masterSheet) throw new Error("MasterData sheet not found.");
    var masterData = masterSheet.getDataRange().getValues();
    var mHeader = masterData[0].map(function(h) { return String(h || '').trim().toLowerCase(); });
    var mRollIdx = mHeader.indexOf("rollno");
    var mEmailIdx = mHeader.indexOf("personal email id");
    if (mRollIdx === -1 || mEmailIdx === -1) { throw new Error("MasterData sheet missing rollNo or Personal Email ID header."); }

    var email = null;
    for (var i = 1; i < masterData.length; i++) {
      if (String(masterData[i][mRollIdx] || '').trim().toUpperCase() === rollNoUpper) {
        email = masterData[i][mEmailIdx];
        break;
      }
    }
    if (!email) { return { success: false, message: "rollNo not found in MasterData." }; }

    var authSheet = getSS().getSheetByName(AUTH_SHEET_NAME);
    if (!authSheet) { throw new Error("Authorisation sheet not found."); }
    var authData = authSheet.getDataRange().getValues();
    var aHeader = authData[0].map(function(h) { return String(h || '').trim().toLowerCase(); });
    var aRollIdx = aHeader.indexOf("rollno");
    var aPassIdx = aHeader.indexOf("password");
    if (aRollIdx === -1 || aPassIdx === -1) { throw new Error("Authorisation sheet missing rollNo or Password header."); }

    var password = null;
    for (var i = 1; i < authData.length; i++) {
      if (String(authData[i][aRollIdx] || '').trim().toUpperCase() === rollNoUpper) {
        password = authData[i][aPassIdx];
        break;
      }
    }
    if (password === null) { return { success: false, message: "rollNo found in MasterData but not in Authorisation data." }; }

    var subject = "Password Reminder for Placement Portal";
    var body = "Hi,\n\nYour login details for the placement portal are:\n\nrollNo: " + rollNoUpper + "\nPassword: " + password + "\n\nDo not share this password with anyone.";
    
    MailApp.sendEmail(email, subject, body, {
      name: PORTAL_EMAIL_NAME
    });

    Logger.log("Sent password reminder to " + email + " for " + rollNoUpper);
    return { success: true, message: "✅ Password has been sent to your registered email." };

  } catch (e) {
    Logger.log("Password reminder failed for " + rollNoUpper + ": " + e.stack);
    return { success: false, message: "❌ Error sending reminder: " + e.message };
  }
}

function ensureResponseSheetHeader_(sheet, fieldsConfig) {
  if (!sheet) {
    Logger.log("ensureResponseSheetHeader_ called with null sheet");
    return [];
  }
  try {
    var masterLabels = [];
    var customLabels = [];
    for (var i = 0; i < fieldsConfig.length; i++) {
      if (fieldsConfig[i].source === 'master') {
        masterLabels.push(fieldsConfig[i].label);
      } else if (fieldsConfig[i].source === 'custom') {
        customLabels.push(fieldsConfig[i].label);
      }
    }

    var headerNeeded = ["rollNo"];
    headerNeeded = headerNeeded.concat(masterLabels);
    headerNeeded = headerNeeded.concat(customLabels);
    headerNeeded.push("Interested");
    headerNeeded.push("Timestamp");

    if (sheet.getLastRow() === 0) {
      sheet.appendRow(headerNeeded);
      return headerNeeded;
    } else {
      var lastCol = sheet.getLastColumn();
      var currentHeader = sheet.getRange(1, 1, 1, lastCol).getValues()[0].map(function(h) {
        return String(h || '').trim();
      });
      var missingCols = [];
      for (var i = 0; i < headerNeeded.length; i++) {
        if (headerNeeded[i] && currentHeader.indexOf(headerNeeded[i]) === -1) {
          missingCols.push(headerNeeded[i]);
        }
      }

      if (missingCols.length > 0) {
        sheet.getRange(1, currentHeader.length + 1, 1, missingCols.length).setValues([missingCols]);
        Logger.log("Added missing headers to " + sheet.getName() + ": " + missingCols.join(', '));
        return currentHeader.concat(missingCols);
      }
      return currentHeader;
    }
  } catch (e) {
    Logger.log("Error in ensureResponseSheetHeader_ for sheet " + sheet.getName() + ": " + e.stack);
    return [];
  }
}

function buildResponseRow_(headerRow, fieldsConfig, studentData, customMap, rollNo, interested, existingResponse) {
  try {
    var rowData = {};

    for (var i = 0; i < fieldsConfig.length; i++) {
      var field = fieldsConfig[i];
      if (field.source === 'master' && studentData.hasOwnProperty(field.key)) {
        rowData[field.label] = studentData[field.key];
      }
    }

    for (var key in customMap) {
      if (customMap.hasOwnProperty(key)) {
        rowData[key] = customMap[key];
      }
    }

    if (existingResponse && existingResponse.exists) {
      for (var i = 0; i < headerRow.length; i++) {
        var headerKey = headerRow[i];
        if (!rowData.hasOwnProperty(headerKey) && existingResponse.data.hasOwnProperty(headerKey)) {
          rowData[headerKey] = existingResponse.data[headerKey];
        }
      }
    }

    rowData["rollNo"] = rollNo;
    rowData["Interested"] = interested;
    rowData["Timestamp"] = new Date();

    var result = [];
    for (var i = 0; i < headerRow.length; i++) {
      result.push(rowData.hasOwnProperty(headerRow[i]) ? rowData[headerRow[i]] : "");
    }
    return result;
  } catch (e) {
    Logger.log("Error in buildResponseRow_: " + e.stack);
    var errorRow = [];
    for (var i = 0; i < headerRow.length; i++) {
      errorRow.push("[ERROR]");
    }
    return errorRow;
  }
}

// ---------------------- ADMIN-ONLY FUNCTIONS ----------------------

function getStudentList(filters) {
  filters = filters || {};
  if (!checkAdminAccess("Viewer")) { return { error: "Access Denied" }; }
  var sheet = getSS().getSheetByName(MASTER_SHEET_NAME);
  if (!sheet || sheet.getLastRow() < 2) { return []; }

  try {
    var data = sheet.getDataRange().getValues();
    var header = data[0].map(function(h) { return String(h || '').trim(); });
    var headerLower = header.map(function(h) { return h.toLowerCase(); });
    var nameIdx = headerLower.indexOf("name");
    var rollIdx = headerLower.indexOf("rollno");
    var emailIdx = headerLower.indexOf("personal email id");

    if (rollIdx === -1) {
      Logger.log("getStudentList: rollNo column missing");
      return { error: "'rollNo' column not found in MasterData." };
    }
    if (nameIdx === -1) Logger.log("getStudentList: Warning - 'Name' column missing");
    if (emailIdx === -1) Logger.log("getStudentList: Warning - 'Personal Email ID' column missing");

    var students = [];
    for (var i = 1; i < data.length; i++) {
      var row = data[i];
      if (!row[rollIdx]) continue;

      var studentObj = {
        name: nameIdx !== -1 ? (row[nameIdx] || "N/A") : "N/A",
        rollNo: row[rollIdx],
        email: emailIdx !== -1 ? row[emailIdx] : null
      };
      for (var j = 0; j < header.length; j++) {
        if (header[j] && !studentObj.hasOwnProperty(header[j])) {
          studentObj[header[j]] = row[j];
        }
      }
      students.push(studentObj);
    }

    if (Object.keys(filters).length > 0) {
      var filtered = [];
      for (var i = 0; i < students.length; i++) {
        var student = students[i];
        var include = true;

        for (var key in filters) {
          if (!filters.hasOwnProperty(key)) continue;
          if (header.indexOf(key) === -1) continue;

          var filterValue = String(filters[key] || '').trim();
          var studentValue = String(student[key] || '').trim();
          if (!filterValue) continue;

          try {
            if (filterValue.indexOf(">=") === 0) {
              if (!(parseFloat(studentValue) >= parseFloat(filterValue.substring(2)))) { include = false; break; }
            } else if (filterValue.indexOf("<=") === 0) {
              if (!(parseFloat(studentValue) <= parseFloat(filterValue.substring(2)))) { include = false; break; }
            } else if (filterValue.indexOf(">") === 0) {
              if (!(parseFloat(studentValue) > parseFloat(filterValue.substring(1)))) { include = false; break; }
            } else if (filterValue.indexOf("<") === 0) {
              if (!(parseFloat(studentValue) < parseFloat(filterValue.substring(1)))) { include = false; break; }
            } else if (filterValue.indexOf("!=") === 0) {
              var val = filterValue.substring(2);
              if (studentValue.toLowerCase() === val.toLowerCase()) { include = false; break; }
            } else if (filterValue.indexOf("!") === 0) {
              var val = filterValue.substring(1);
              if (studentValue.toLowerCase() === val.toLowerCase()) { include = false; break; }
            } else if (filterValue.indexOf("=") === 0) {
              if (studentValue.toLowerCase() !== filterValue.substring(1).toLowerCase()) { include = false; break; }
            } else if (filterValue.indexOf("*") === 0 && filterValue.lastIndexOf("*") === filterValue.length - 1) {
              if (studentValue.toLowerCase().indexOf(filterValue.substring(1, filterValue.length - 1).toLowerCase()) === -1) { include = false; break; }
            } else if (filterValue.lastIndexOf("*") === filterValue.length - 1) {
              if (studentValue.toLowerCase().indexOf(filterValue.substring(0, filterValue.length - 1).toLowerCase()) !== 0) { include = false; break; }
            } else {
              if (studentValue.toLowerCase() !== filterValue.toLowerCase()) { include = false; break; }
            }
          } catch (e) {
            console.error("Filter error on key \"" + key + "\", value \"" + filterValue + "\": " + e.message);
            Logger.log("Filter error on key \"" + key + "\", value \"" + filterValue + "\", studentVal \"" + studentValue + "\": " + e.stack);
            include = false;
            break;
          }
        }

        if (include) {
          filtered.push(student);
        }
      }
      students = filtered;
    }

    var result = [];
    for (var i = 0; i < students.length; i++) {
      result.push({
        name: students[i].name,
        rollNo: students[i].rollNo,
        email: students[i].email
      });
    }
    return result;
  } catch (e) {
    Logger.log("Error in getStudentList: " + e.stack);
    return { error: "Server error retrieving student list." };
  }
}

function sendEmailToStudents(formName, studentEmails, subject, body, options) {
  if (!checkAdminAccess("Editor")) { return { success: false, message: "Access Denied" }; }
  if (!Array.isArray(studentEmails) || studentEmails.length === 0) {
    return { success: false, message: "No student emails provided." };
  }
  try {
    var formLink = ScriptApp.getService().getUrl() + "?formName=" + encodeURIComponent(formName);
    var emailBody = body.replace(/\{\{formLink\}\}/g, formLink).replace(/\{\{formName\}\}/g, formName);
    var actor = Session.getActiveUser().getEmail() || "System";

    var emailOptions = {
      name: PORTAL_EMAIL_NAME
    };

    var successCount = 0, failCount = 0, errors = [];
    for (var i = 0; i < studentEmails.length; i++) {
      var email = studentEmails[i];
      if (email && String(email).indexOf('@') !== -1) {
        try {
          MailApp.sendEmail(email, subject, emailBody, emailOptions);
          successCount++;
        } catch (e) {
          console.error("Failed to send email to " + email + ": " + e.message);
          Logger.log("Failed email to " + email + ": " + e.stack);
          failCount++;
          errors.push(email + ": " + e.message);
        }
      } else {
        Logger.log("Skipping invalid email address: " + email);
        failCount++;
        errors.push(email + ": Invalid address");
      }
    }

    var details = "Sent email for '" + formName + "' to " + successCount + " students. Failed: " + failCount + ".";
    if (failCount > 0) {
      var errorList = [];
      for (var i = 0; i < Math.min(5, errors.length); i++) {
        errorList.push(errors[i]);
      }
      details += " Errors: " + errorList.join('; ');
    }
    logAdminAction_("SEND EMAIL", details, actor);

    var message = "Sent " + successCount + " emails.";
    if (failCount > 0) { message += " Failed for " + failCount + ". Check logs for details."; }
    return { success: true, message: message };
  } catch (e) {
    Logger.log("Error in sendEmailToStudents: " + e.stack);
    return { success: false, message: "Server error sending emails: " + e.message };
  }
}

function findAdminEmail(searchTerm) {
  if (!checkAdminAccess("Editor")) { return { error: "Access Denied" }; }
  try {
    var safeSearchTerm = searchTerm.replace(/"/g, '\\"').replace(/'/g, "\\'");
    
    var query = safeSearchTerm ? `(subject:("${safeSearchTerm}") OR from:("${safeSearchTerm}")) in:inbox` : 'in:inbox';

    var threads = GmailApp.search(query, 0, 15);
    
    var messages = [];
    for (var i = 0; i < threads.length; i++) {
      var thread = threads[i];
      var msg = thread.getMessages()[thread.getMessageCount() - 1]; 
      messages.push({
        id: msg.getId(),
        subject: msg.getSubject(),
        from: msg.getFrom(),
        date: msg.getDate().toISOString() 
      });
    }
    return { success: true, messages: messages };
  } catch (e) {
    console.error("Gmail search failed: " + e.message);
    Logger.log("Gmail search error: " + e.stack);
    return { error: "Gmail search error: " + e.message + ". Check search term syntax." };
  }
}

function forwardAdminEmail(messageId, studentEmails) {
  if (!checkAdminAccess("Editor")) { return { success: false, message: "Access Denied" }; }
  if (!Array.isArray(studentEmails) || studentEmails.length === 0) {
    return { success: false, message: "No student emails provided." };
  }
  try {
    var message = GmailApp.getMessageById(messageId);
    if (!message) {
      return { success: false, message: "Email message not found (ID: " + messageId + ")." };
    }
    var successCount = 0, failCount = 0, errors = [];
    var adminEmail = Session.getActiveUser().getEmail();

    var forwardOptions = {
      name: PORTAL_EMAIL_NAME
    };

    for (var i = 0; i < studentEmails.length; i++) {
      var email = studentEmails[i];
      if (email && String(email).indexOf('@') !== -1) {
        try {
          message.forward(email, forwardOptions);
          successCount++;
          Utilities.sleep(1000); 
        } catch (e) {
          console.error("Failed to forward to " + email + ": " + e.message);
          Logger.log("Failed forward to " + email + ": " + e.stack);
          failCount++;
          errors.push(email + ": " + e.message);
        }
      } else {
        Logger.log("Skipping invalid email address for forward: " + email);
        failCount++;
        errors.push(email + ": Invalid address");
      }
    }
    var subjectPreview = message.getSubject().substring(0, 50);
    var details = "Forwarded '" + subjectPreview + "...' to " + successCount + " students. Failed: " + failCount + ".";
    if (failCount > 0) {
      var errorList = [];
      for (var i = 0; i < Math.min(5, errors.length); i++) {
        errorList.push(errors[i]);
      }
      details += " Errors: " + errorList.join('; ');
    }
    logAdminAction_("FORWARD EMAIL", details, adminEmail);

    var messageTxt = "Forwarded to " + successCount + " students.";
    if (failCount > 0) { messageTxt += " Failed for " + failCount + ". Check logs."; }
    return { success: true, message: messageTxt };
  } catch (e) {
    console.error("Gmail forward failed: " + e.message);
    Logger.log("Gmail forward error: " + e.stack);
    return { success: false, message: "Error forwarding email: " + e.message };
  }
}

function listFormsPublic_() {
  try {
    var sheet = ensureFormsConfigSchema_();
    var lastRow = sheet.getLastRow();
    if (lastRow < 2) return [];

    var data = sheet.getRange(1, 1, lastRow, sheet.getLastColumn()).getValues();
    var header = data[0];
    var now = Date.now();
    var forms = [];

    var nameIdx = header.indexOf("Form Name");
    var acceptingIdx = header.indexOf("Accepting");
    var deadlineIdx = header.indexOf("Deadline");
    var sheetIdx = header.indexOf("Response Sheet");
    var allowedIdx = header.indexOf("Allowed Students");

    if (nameIdx === -1 || acceptingIdx === -1 || deadlineIdx === -1 || sheetIdx === -1 || allowedIdx === -1) {
      Logger.log("listFormsPublic_: FormsConfig sheet missing required headers.");
      return [];
    }

    for (var i = 1; i < data.length; i++) {
      var row = data[i];
      var formName = String(row[nameIdx] || '').trim();
      if (formName) {
        var manualAccepting = row[acceptingIdx] !== false;
        var deadlineVal = row[deadlineIdx];
        var deadlineMs = (deadlineVal instanceof Date) ? deadlineVal.getTime() : 0;
        forms.push({
          formName: formName,
          isOpen: manualAccepting && (!deadlineMs || now < deadlineMs),
          deadlineMs: deadlineMs,
          responseSheet: row[sheetIdx],
          allowedStudents: row[allowedIdx] || ""
        });
      }
    }
    return forms;
  } catch (e) {
    Logger.log("Error in listFormsPublic_: " + e.stack);
    return [];
  }
}

function getAvailableFields() {
  if (!checkAdminAccess("Viewer")) { return []; }
  try {
    var sheet = getSS().getSheetByName(MASTER_SHEET_NAME);
    if (!sheet) return [];
    var lastCol = sheet.getLastColumn();
    if (lastCol === 0) return [];
    var header = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
    var result = [];
    for (var i = 0; i < header.length; i++) {
      var h = header[i];
      if (h && String(h).trim() !== '') {
        result.push(h);
      }
    }
    return result;
  } catch (e) {
    Logger.log("Error in getAvailableFields: " + e.stack);
    return [];
  }
}

function createNewForm(formData) {
  if (!checkAdminAccess("Editor")) { return { success: false, message: "Access Denied" }; }
  var actor = Session.getActiveUser().getEmail();
  try {
    var sheet = ensureFormsConfigSchema_();
    var formName = String(formData.formName || '').trim();
    if (!formName) {
      return { success: false, message: "Form Name cannot be empty." };
    }
    if (findRowByValue_(sheet, 1, formName)) {
      logAdminAction_("CREATE FORM FAILED", "Duplicate form name: " + formName, actor);
      return { success: false, message: "Form Name already exists!" };
    }

    var fields = normalizeFieldsConfig_(formData.fields || []);

    var lastCol = sheet.getLastColumn();
    var header = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
    var row = [];
    for (var i = 0; i < header.length; i++) {
      var h = header[i];
      switch (h) {
        case "Form Name": row.push(formName); break;
        case "Fields to Show": row.push(JSON.stringify(fields)); break;
        case "Created Date": row.push(new Date()); break;
        case "Response Sheet": row.push("Responses_" + formName.replace(/[^a-zA-Z0-9_]/g, "_")); break;
        case "Accepting": row.push(formData.accepting !== false); break;
        case "Deadline":
          if (formData.deadlineIso) {
            var deadlineDate = new Date(formData.deadlineIso);
            row.push(isNaN(deadlineDate.getTime()) ? "" : deadlineDate);
          } else {
            row.push("");
          }
          break;
        case "Description": row.push(formData.description || ""); break;
        case "File Link": row.push(formData.fileLink || ""); break;
        case "Allowed Students": row.push(formData.allowedStudents || ""); break;
        default: row.push("");
      }
    }

    sheet.appendRow(row);
    logAdminAction_("CREATE FORM SUCCESS", "Form '" + formName + "' created.", actor);
    return { success: true, message: "✅ Form created!", url: ScriptApp.getService().getUrl() + "?formName=" + encodeURIComponent(formName) };
  } catch (e) {
    Logger.log("Error in createNewForm: " + e.stack);
    return { success: false, message: "Server error creating form: " + e.message };
  }
}

function setFormAccepting(formName, isAccepting) {
  if (!checkAdminAccess("Editor")) { return { success: false, message: "Access Denied" }; }
  try {
    var sheet = ensureFormsConfigSchema_();
    var found = findRowByValue_(sheet, 1, formName);
    if (!found) { return { success: false, message: "Form not found." }; }

    var lastCol = sheet.getLastColumn();
    var header = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
    var acceptingIdx = header.indexOf("Accepting");

    if (acceptingIdx !== -1) {
      sheet.getRange(found.row, acceptingIdx + 1).setValue(isAccepting);
      logAdminAction_("FORM TOGGLE", "Set '" + formName + "' accepting to " + isAccepting, Session.getActiveUser().getEmail());
      return { success: true, message: "Form status updated." };
    } else {
      return { success: false, message: "Could not find 'Accepting' column." };
    }
  } catch (e) {
    Logger.log("Error in setFormAccepting: " + e.stack);
    return { success: false, message: "Server error updating form status: " + e.message };
  }
}

function getAllForms() {
  if (!checkAdminAccess("Viewer")) { return { success: false, message: "Access Denied" }; }
  try {
    var ss = getResponsesSS();
    var sheet = ensureFormsConfigSchema_();
    var lastRow = sheet.getLastRow();
    if (lastRow < 2) { return { success: true, forms: [] }; }

    var data = sheet.getRange(1, 1, lastRow, sheet.getLastColumn()).getValues();
    var header = data[0];
    var now = Date.now();

    var nameIdx = header.indexOf("Form Name");
    var fieldsIdx = header.indexOf("Fields to Show");
    var acceptIdx = header.indexOf("Accepting");
    var deadIdx = header.indexOf("Deadline");
    var respIdx = header.indexOf("Response Sheet");
    var descIdx = header.indexOf("Description");
    var fileIdx = header.indexOf("File Link");
    var allowIdx = header.indexOf("Allowed Students");

    if (nameIdx === -1 || fieldsIdx === -1 || acceptIdx === -1 || deadIdx === -1 || respIdx === -1 || allowIdx === -1) {
      Logger.log("getAllForms: FormsConfig sheet missing required headers.");
      return { success: false, message: "Server config error: FormsConfig headers missing." };
    }

    var forms = [];
    for (var i = 1; i < data.length; i++) {
      var row = data[i];
      var formName = String(row[nameIdx] || '').trim();
      if (!formName) continue;

      var deadlineVal = row[deadIdx];
      var deadlineMs = (deadlineVal instanceof Date) ? deadlineVal.getTime() : 0;
      var accepting = row[acceptIdx] !== false;
      var respSheetName = row[respIdx];
      var respSheet = respSheetName ? ss.getSheetByName(respSheetName) : null;

      forms.push({
        formName: formName,
        fields: normalizeFieldsConfig_(row[fieldsIdx]),
        accepting: accepting,
        deadlineMs: deadlineMs,
        isOpen: accepting && (!deadlineMs || now < deadlineMs),
        responses: respSheet ? Math.max(countSubmittedStudents(respSheet) - 1, 0) : 0,
        url: ScriptApp.getService().getUrl() + "?formName=" + encodeURIComponent(formName),
        description: row[descIdx] || "",
        fileLink: row[fileIdx] || "",
        allowedStudents: row[allowIdx] || ""
      });
    }

    return { success: true, forms: forms };
  } catch (e) {
    Logger.log("Error in getAllForms: " + e.stack);
    return { success: false, message: "Server error getting form list: " + e.message };
  }
}

function countSubmittedStudents(sheet) {
  const data = sheet.getDataRange().getValues();
  let count = 0;
  for (let i = 0; i < data.length; i++) {
    if (data[i].some(cell => cell !== "")) {
      count++;
    }
  }
  return count;
}

function setAdminRole(email, role) {
  if (!checkAdminAccess("SuperAdmin")) { return { success: false, message: "Access denied." }; }
  try {
    var ss = getSS();
    var sheet = ss.getSheetByName(ADMIN_ROLES_SHEET);
    if (!sheet) {
      sheet = ss.insertSheet(ADMIN_ROLES_SHEET);
      sheet.appendRow(["Email", "Role", "Last Updated"]);
    }
    var found = findRowByValue_(sheet, 0, email);
    if (found) {
      sheet.getRange(found.row, 2, 1, 2).setValues([[role, new Date()]]);
    } else {
      sheet.appendRow([email, role, new Date()]);
    }
    logAdminAction_("RBAC CHANGE", "Set role of " + email + " to " + role, Session.getActiveUser().getEmail());
    return { success: true, message: "✅ Role for " + email + " set to " + role + "." };
  } catch (e) {
    Logger.log("Error in setAdminRole: " + e.stack);
    return { success: false, message: "Server error setting admin role: " + e.message };
  }
}

function getAdminRolesList() {
  if (!checkAdminAccess("Viewer")) { return { success: false, message: "Access denied." }; }
  try {
    var sheet = getSS().getSheetByName(ADMIN_ROLES_SHEET);
    if (!sheet || sheet.getLastRow() < 2) { return { success: true, roles: [] }; }
    var data = sheet.getRange(2, 1, sheet.getLastRow() - 1, 2).getValues();
    var roles = [];
    for (var i = 0; i < data.length; i++) {
      roles.push({ email: data[i][0], role: data[i][1] });
    }
    return { success: true, roles: roles };
  } catch (e) {
    Logger.log("Error in getAdminRolesList: " + e.stack);
    return { success: false, message: "Server error getting admin roles: " + e.message };
  }
}

function updateFormProperties(formName, properties) {
  if (!checkAdminAccess("Editor")) { return { success: false, message: "Access Denied" }; }
  try {
    var sheet = ensureFormsConfigSchema_();
    var found = findRowByValue_(sheet, 1, formName);
    if (!found) { return { success: false, message: "Form not found." }; }

    var lastCol = sheet.getLastColumn();
    var header = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
    var changes = [];

    var propMap = {
      "description": "Description",
      "deadlineIso": "Deadline",
      "fileLink": "File Link",
      "allowedStudents": "Allowed Students"
    };

    for (var key in propMap) {
      if (properties.hasOwnProperty(key)) {
        var colName = propMap[key];
        var colIdx = header.indexOf(colName);
        if (colIdx !== -1) {
          var value = properties[key];
          if (key === 'deadlineIso') {
            if (value) {
              var deadlineDate = new Date(value);
              value = isNaN(deadlineDate.getTime()) ? "" : deadlineDate;
            } else {
              value = "";
            }
          }
          if (colIdx < found.data.length) {
            if (String(found.data[colIdx] || '') !== String(value)) {
              sheet.getRange(found.row, colIdx + 1).setValue(value);
              changes.push(colName);
            }
          } else {
            sheet.getRange(found.row, colIdx + 1).setValue(value);
            changes.push(colName);
          }
        } else {
          Logger.log("updateFormProperties: Column not found in FormsConfig header - " + colName);
        }
      }
    }

    if (changes.length > 0) {
      logAdminAction_("UPDATE FORM PROPS", "Updated " + changes.join(', ') + " for '" + formName + "'", Session.getActiveUser().getEmail());
      return { success: true, message: "✅ Form properties updated." };
    } else {
      return { success: true, message: "No changes detected." };
    }
  } catch (e) {
    Logger.log("Error in updateFormProperties: " + e.stack);
    return { success: false, message: "Server error updating properties: " + e.message };
  }
}

function updateFormFields(formName, updatedFields) {
  if (!checkAdminAccess("Editor")) { return { success: false, message: "Access Denied" }; }
  try {
    var sheet = ensureFormsConfigSchema_();
    var found = findRowByValue_(sheet, 1, formName);
    if (!found) { return { success: false, message: "Form not found" }; }

    var cleanFields = normalizeFieldsConfig_(updatedFields);

    var lastCol = sheet.getLastColumn();
    var header = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
    var fieldsColIndex = header.indexOf("Fields to Show");
    if (fieldsColIndex === -1) { return { success: false, message: "'Fields to Show' column not found." }; }

    var newFieldsJson = JSON.stringify(cleanFields);
    var oldFieldsJson = fieldsColIndex < found.data.length ? String(found.data[fieldsColIndex] || '') : "";

    if (newFieldsJson !== oldFieldsJson) {
      sheet.getRange(found.row, fieldsColIndex + 1).setValue(newFieldsJson);

      var cfg = getFormConfig(formName);
      if (!cfg.error && cfg.responseSheet) {
        var ss = getResponsesSS();
        var respSheet = ss.getSheetByName(cfg.responseSheet);
        if (!respSheet) {
          respSheet = ss.insertSheet(cfg.responseSheet);
        }
        ensureResponseSheetHeader_(respSheet, cfg.fields);
      } else {
        console.error("Response sheet \"" + cfg.responseSheet + "\" not found or config error for form \"" + formName + "\".");
        Logger.log("Response sheet \"" + cfg.responseSheet + "\" not found or config error for form \"" + formName + "\". Config Error: " + cfg.error);
      }

      logAdminAction_("UPDATE FORM FIELDS", "Updated fields for '" + formName + "'", Session.getActiveUser().getEmail());
      return { success: true, message: "✅ Form fields updated." };
    } else {
      return { success: true, message: "No field changes detected." };
    }
  } catch (e) {
    Logger.log("Error in updateFormFields: " + e.stack);
    return { success: false, message: "Server error updating fields: " + e.message };
  }
}

function duplicateForm(formName, newName) {
  if (!checkAdminAccess("Editor")) {
    return { success: false, message: "Access Denied" };
  }

  if (!newName || newName.trim() === "") {
    return { success: false, message: "New name cannot be empty." };
  }
  var cleanNewName = newName.trim();

  try {
    var sheet = ensureFormsConfigSchema_();

    if (findRowByValue_(sheet, 1, cleanNewName)) {
      return { success: false, message: "The name '" + cleanNewName + "' already exists. Please choose a different name." };
    }

    var found = findRowByValue_(sheet, 1, formName);
    if (!found) {
      return { success: false, message: "Original form not found" };
    }

    var newRow = found.data.slice();
    var lastCol = sheet.getLastColumn();
    var header = sheet.getRange(1, 1, 1, lastCol).getValues()[0];

    var nameIdx = header.indexOf("Form Name");
    var sheetIdx = header.indexOf("Response Sheet");
    var createdIdx = header.indexOf("Created Date");
    var acceptingIdx = header.indexOf("Accepting");
    var deadlineIdx = header.indexOf("Deadline");

    if (nameIdx === -1 || sheetIdx === -1 || createdIdx === -1 || acceptingIdx === -1 || deadlineIdx === -1) {
      return { success: false, message: "Cannot duplicate: FormsConfig headers missing." };
    }

    newRow[nameIdx] = cleanNewName;
    newRow[sheetIdx] = "Responses_" + cleanNewName.replace(/[^a-zA-Z0-9_]/g, "_");
    newRow[createdIdx] = new Date();
    newRow[acceptingIdx] = false;
    newRow[deadlineIdx] = "";

    sheet.appendRow(newRow);
    logAdminAction_("DUPLICATE FORM", "Duplicated '" + formName + "' to '" + cleanNewName + "'", Session.getActiveUser().getEmail());
    return { success: true, message: "✅ Form duplicated." };
  } catch (e) {
    Logger.log("Error in duplicateForm: " + e.stack);
    return { success: false, message: "Server error duplicating form: " + e.message };
  }
}

function deleteForm(formName) {
  if (!checkAdminAccess("SuperAdmin")) { return { success: false, message: "Access Denied" }; }
  try {
    var sheet = ensureFormsConfigSchema_();
    var found = findRowByValue_(sheet, 1, formName);
    if (!found) { return { success: false, message: "Form not found." }; }

    sheet.deleteRow(found.row);
    logAdminAction_("DELETE FORM", "Deleted form '" + formName + "'", Session.getActiveUser().getEmail());
    return { success: true, message: "✅ Form deleted." };
  } catch (e) {
    Logger.log("Error in deleteForm: " + e.stack);
    return { success: false, message: "Server error deleting form: " + e.message };
  }
}

function getStudentDetails(searchTerm) {
  if (!checkAdminAccess("Editor")) { return { error: "Access Denied" }; }
  
  if (!searchTerm || !searchTerm.trim()) {
    return { success: false, message: "Search term is required" };
  }
  
  var searchValue = String(searchTerm).trim();
  var foundStudent = null;
  
  try {
    var sheet = getSS().getSheetByName(MASTER_SHEET_NAME);
    if (!sheet || sheet.getLastRow() < 2) {
      return { success: false, message: "No student data found in MasterData sheet" };
    }

    var data = sheet.getDataRange().getValues();
    var header = data[0].map(function(h) { return String(h || '').trim(); });
    var headerLower = header.map(function(h) { return h.toLowerCase(); });
    
    var rollIdx = headerLower.indexOf("rollno");
    var nameIdx = headerLower.indexOf("name");
    var emailIdx = headerLower.indexOf("personal email id");
    
    if (rollIdx === -1) {
      return { success: false, message: "rollNo column not found in MasterData" };
    }

    for (var i = 1; i < data.length; i++) {
      var row = data[i];
      if (!row[rollIdx]) continue;
      
      var rollNo = String(row[rollIdx] || "").trim();
      var name = nameIdx !== -1 ? String(row[nameIdx] || "").trim() : "";
      var email = emailIdx !== -1 ? String(row[emailIdx] || "").trim() : "";
      
      if (rollNo.toUpperCase() === searchValue.toUpperCase() ||
          name.toLowerCase().indexOf(searchValue.toLowerCase()) !== -1 ||
          email.toLowerCase().indexOf(searchValue.toLowerCase()) !== -1) {
        
        foundStudent = {};
        for (var j = 0; j < header.length; j++) {
          if (header[j]) {
            foundStudent[header[j]] = row[j];
          }
        }
        
        if (!foundStudent.rollNo && foundStudent.rollNo) {
          foundStudent.rollNo = foundStudent.rollNo;
        }
        if (!foundStudent.Name && foundStudent.name) {
          foundStudent.Name = foundStudent.name;
        }
        if (!foundStudent.Email && foundStudent["College Email ID"]) {
          foundStudent.Email = foundStudent["College Email ID"];
        }
        break;
      }
    }

    if (!foundStudent) {
      return { success: false, message: "No student found matching '" + searchValue + "'. Try searching by Roll Number, Name, or Email." };
    }

    var rollNoUpper = String(foundStudent.rollNo || foundStudent.rollNo || "").trim().toUpperCase();
    try {
      var authSheet = getSS().getSheetByName(AUTH_SHEET_NAME);
      if (!authSheet) throw new Error("Authorisation sheet not found.");
      var authData = authSheet.getDataRange().getValues();
      var authHeader = authData[0].map(function(h) { return String(h || '').trim().toLowerCase(); });
      var authRollIdx = authHeader.indexOf("rollno");
      var passIdx = authHeader.indexOf("password");
      
      foundStudent.Password = '';
      if (authRollIdx !== -1 && passIdx !== -1) {
        for (var r = 1; r < authData.length; r++) {
          if (String(authData[r][authRollIdx] || '').trim().toUpperCase() === rollNoUpper) {
            foundStudent.Password = authData[r][passIdx] || '';
            break;
          }
        }
      }
    } catch (e) {
      Logger.log("Error fetching password for " + rollNoUpper + ": " + e.stack);
      foundStudent.Password = "[Error fetching password]";
    }

    return { success: true, data: foundStudent };
  } catch (e) {
    Logger.log("Error in getStudentDetails: " + e.stack);
    return { success: false, message: "Server error: " + e.message };
  }
}

function debugMasterDataStructure() {
  if (!checkAdminAccess("Viewer")) { return { error: "Access Denied" }; }
  
  try {
    var sheet = getSS().getSheetByName(MASTER_SHEET_NAME);
    if (!sheet) {
      return { success: false, message: "MasterData sheet not found" };
    }
    
    if (sheet.getLastRow() < 1) {
      return { success: false, message: "MasterData sheet is empty" };
    }
    
    var header = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
    var rowCount = sheet.getLastRow() - 1;
    
    return { 
      success: true, 
      headers: header,
      rowCount: rowCount,
      sheetName: MASTER_SHEET_NAME
    };
  } catch (e) {
    Logger.log("Error in debugMasterDataStructure: " + e.stack);
    return { success: false, message: "Error: " + e.message };
  }
}

function updateStudentDetails(rollNo, rowID, dataToUpdate) {
  var userEmail = Session.getActiveUser().getEmail();
  var isStudentUpdate = !userEmail;

  if (!isStudentUpdate && !checkAdminAccess("Editor")) {
    return { success: false, message: "Access Denied" };
  }

  var rollNoUpper = String(rollNo).trim().toUpperCase();
  var changes = [];
  var actor = userEmail || rollNo;

  try {
    if (dataToUpdate.hasOwnProperty('Password') && dataToUpdate.Password !== undefined) {
      var authSheet = getSS().getSheetByName(AUTH_SHEET_NAME);
      if (!authSheet) throw new Error("Authorisation sheet not found.");
      var authData = authSheet.getDataRange().getValues();
      var aHeader = authData[0].map(function(h) { return String(h || '').trim().toLowerCase(); });
      var aRollIdx = aHeader.indexOf("rollno");
      var aPassIdx = aHeader.indexOf("password");
      if (aRollIdx === -1 || aPassIdx === -1) throw new Error("Auth sheet headers invalid.");

      var foundAuth = false;
      for (var r = 1; r < authData.length; r++) {
        if (String(authData[r][aRollIdx] || '').trim().toUpperCase() === rollNoUpper) {
          if (String(authData[r][aPassIdx]) !== String(dataToUpdate.Password)) {
            authSheet.getRange(r + 1, aPassIdx + 1).setValue(dataToUpdate.Password);
            changes.push("Password");
          }
          foundAuth = true;
          break;
        }
      }
      if (!foundAuth && dataToUpdate.Password !== '') {
        if (authSheet.getLastRow() === 0) { authSheet.appendRow(['rollNo', 'Password', 'Timestamp']); }
        authSheet.appendRow([rollNoUpper, dataToUpdate.Password, new Date()]);
        changes.push("Password (Created)");
      }
    }

    var masterSheet = getSS().getSheetByName(MASTER_SHEET_NAME);
    if (!masterSheet) throw new Error("MasterData sheet not found.");
    var masterHeader = masterSheet.getRange(1, 1, 1, masterSheet.getLastColumn()).getValues()[0].map(function(h) { return String(h || '').trim(); });
    var masterChangesMade = false;
    var foundMaster = false;

    if (rowID && isStudentUpdate) {
        Logger.log("Using fast update path for row " + rowID);
        var rowToUpdate = masterSheet.getRange(rowID, 1, 1, masterHeader.length).getValues()[0];
        
        for (var col = 0; col < masterHeader.length; col++) {
          var key = masterHeader[col];
          if (key && dataToUpdate.hasOwnProperty(key) && key.toLowerCase() !== 'password' && key.toLowerCase() !== 'rollno') {
            if (String(rowToUpdate[col] || '') !== String(dataToUpdate[key] || '')) {
              rowToUpdate[col] = dataToUpdate[key];
              changes.push(key);
              masterChangesMade = true;
            }
          }
        }
        if (masterChangesMade) {
          masterSheet.getRange(rowID, 1, 1, rowToUpdate.length).setValues([rowToUpdate]);
        }
        foundMaster = true;

    } else {
        Logger.log("Using slow update path (search by rollNo) for " + rollNoUpper);
        
        var mRollIdx = -1;
        for (var i = 0; i < masterHeader.length; i++) {
            if (masterHeader[i].toLowerCase() === "rollno") {
                mRollIdx = i;
                break;
            }
        }
        if (mRollIdx === -1) throw new Error("MasterData 'rollNo' column not found.");

        var masterData = masterSheet.getDataRange().getValues(); 
        
        for (var r = 1; r < masterData.length; r++) {
            if (String(masterData[r][mRollIdx] || '').trim().toUpperCase() === rollNoUpper) {
                foundMaster = true;
                var rowToUpdate = masterData[r].slice();
                for (var col = 0; col < masterHeader.length; col++) {
                    var key = masterHeader[col];
                    if (key && dataToUpdate.hasOwnProperty(key) && key.toLowerCase() !== 'password' && key.toLowerCase() !== 'rollno') {
                        if (String(rowToUpdate[col] || '') !== String(dataToUpdate[key] || '')) {
                            rowToUpdate[col] = dataToUpdate[key];
                            changes.push(key);
                            masterChangesMade = true;
                        }
                    }
                }
                if (masterChangesMade) {
                    masterSheet.getRange(r + 1, 1, 1, rowToUpdate.length).setValues([rowToUpdate]);
                }
                break;
            }
        }
    }

    if (!foundMaster && changes.length > 0 && changes[0].indexOf("Password") === -1) {
      return { success: false, message: "Student not found in MasterData." };
    }

    if (changes.length > 0) {
      logAdminAction_("STUDENT UPDATE", "Updated " + changes.join(', ') + " for " + rollNoUpper, actor);
      return { success: true, message: "✅ Student updated." };
    } else {
      return { success: true, message: "No changes detected." };
    }

  } catch (e) {
    Logger.log("Error in updateStudentDetails for " + rollNoUpper + ": " + e.stack);
    return { success: false, message: "Server error updating student: " + e.message };
  }
}

function authenticateAndGetRowID(rollNo, password) {
  var res = authenticateStudent_(rollNo, password);
  if (res.ok) {
    return res; 
  } else {
    return { error: res.error };
  }
}

function resetStudentPassword(rollNo) {
  if (!checkAdminAccess("Editor")) { return { success: false, message: "Access Denied" }; }
  var rollNoUpper = String(rollNo).trim().toUpperCase();
  var newPassword = "pass" + Math.floor(1000 + Math.random() * 9000);

  try {
    var result = updateStudentDetails(rollNoUpper, null, { "Password": newPassword });

    if (result.success && result.message.indexOf("updated") !== -1) {
      if (result.message.indexOf("Password") !== -1) {
        logAdminAction_("PASSWORD RESET", "Reset password for " + rollNoUpper, Session.getActiveUser().getEmail());
        return { success: true, message: "✅ Password reset to: " + newPassword };
      } else {
        return { success: false, message: "Password reset failed: Update reported success but password change not detected." };
      }
    } else if (result.success) {
      var studentExists = getStudentMasterDataByRoll_(rollNoUpper) !== null;
      if (studentExists) {
        return { success: false, message: "Password reset failed: Could not update password (already set?)." };
      } else {
        return { success: false, message: "Password reset failed: Student " + rollNoUpper + " not found." };
      }
    } else {
      return { success: false, message: "Password reset failed: " + result.message };
    }
  } catch (e) {
    Logger.log("Error in resetStudentPassword: " + e.stack);
    return { success: false, message: "Server error resetting password: " + e.message };
  }
}

function processStudentCsv(csvData) {
  if (!checkAdminAccess("SuperAdmin")) { return { success: false, message: "Access Denied" }; }
  try {
    var rows = Utilities.parseCsv(csvData);
    if (rows.length < 2) { return { success: false, message: "CSV has no data rows." }; }

    var csvHeader = rows[0].map(function(h) { return String(h || '').trim(); });
    var csvHeaderLower = csvHeader.map(function(h) { return h.toLowerCase(); });
    var rollIdx = csvHeaderLower.indexOf("rollno");
    var emailIdx = csvHeaderLower.indexOf("personal email id");
    var nameIdx = csvHeaderLower.indexOf("name");

    if (rollIdx === -1 || emailIdx === -1 || nameIdx === -1) {
      return { success: false, message: "CSV must contain 'rollNo', 'Name', and 'Personal Email ID' columns." };
    }

    var ss = getSS();
    var masterSheet = ss.getSheetByName(MASTER_SHEET_NAME);
    var authSheet = ss.getSheetByName(AUTH_SHEET_NAME);
    if (!masterSheet || !authSheet) { return { success: false, message: "MasterData or Authorisation sheet missing." }; }

    var masterData = masterSheet.getDataRange().getValues();
    var masterHeader = masterData[0].map(function(h) { return String(h || '').trim(); });
    var masterRollIdx = -1;
    for (var i = 0; i < masterHeader.length; i++) {
      if (masterHeader[i].toLowerCase() === "rollno") {
        masterRollIdx = i;
        break;
      }
    }
    if (masterRollIdx === -1) { return { success: false, message: "'rollNo' column not found in MasterData." }; }

    var masterMap = {};
    for (var i = 1; i < masterData.length; i++) {
      var row = masterData[i];
      if (row[masterRollIdx]) {
        var key = String(row[masterRollIdx]).trim().toUpperCase();
        masterMap[key] = { row: i + 1, data: row };
      }
    }

    var authData = authSheet.getDataRange().getValues();
    var authHeader = (authData.length > 0 ? authData[0] : []).map(function(h) { return String(h || '').trim(); });
    var authHeaderLower = authHeader.map(function(h) { return h.toLowerCase(); });
    var authRollIdx = authHeaderLower.indexOf("rollno");
    var authPassIdx = authHeaderLower.indexOf("password");
    var authMap = {};
    if (authRollIdx !== -1) {
      for (var i = 1; i < authData.length; i++) {
        var row = authData[i];
        if (row[authRollIdx]) {
          var key = String(row[authRollIdx]).trim().toUpperCase();
          authMap[key] = { row: i + 1, password: authPassIdx !== -1 ? row[authPassIdx] : null };
        }
      }
    } else {
      Logger.log("processStudentCsv: 'rollNo' column not found in Authorisation sheet during check.");
    }

    var newMasterRows = [];
    var masterUpdates = [];
    var newAuthRows = [];
    var updatedCount = 0;
    var newCount = 0;

    for (var i = 1; i < rows.length; i++) {
      var csvRow = rows[i];
      var rollNo = String(csvRow[rollIdx] || '').trim().toUpperCase();
      if (!rollNo) continue;

      var masterRowData = [];
      for (var j = 0; j < masterHeader.length; j++) {
        var csvIdx = csvHeader.indexOf(masterHeader[j]);
        masterRowData.push(csvIdx !== -1 ? (csvRow[csvIdx] || "") : "");
      }

      if (masterMap[rollNo]) {
        var existingRowIndex = masterMap[rollNo].row;
        var existingData = masterMap[rollNo].data;
        var needsUpdate = false;
        for (var j = 0; j < masterRowData.length && j < existingData.length; j++) {
          if (String(masterRowData[j]) !== String(existingData[j])) {
            needsUpdate = true;
            break;
          }
        }
        if (needsUpdate) {
          masterUpdates.push({ range: masterSheet.getRange(existingRowIndex, 1, 1, masterRowData.length), values: [masterRowData] });
          updatedCount++;
        }
      } else {
        newMasterRows.push(masterRowData);
        newCount++;
      }

      if (!authMap[rollNo]) {
        var newPassword = "pass" + Math.floor(1000 + Math.random() * 9000);
        newAuthRows.push([rollNo, newPassword, new Date()]);
      }
    }

    if (masterUpdates.length > 0) {
      for (var i = 0; i < masterUpdates.length; i++) {
        masterUpdates[i].range.setValues(masterUpdates[i].values);
      }
      Logger.log("processStudentCsv: Updated " + masterUpdates.length + " rows in MasterData.");
    }
    if (newMasterRows.length > 0) {
      masterSheet.getRange(masterSheet.getLastRow() + 1, 1, newMasterRows.length, newMasterRows[0].length).setValues(newMasterRows);
      Logger.log("processStudentCsv: Added " + newMasterRows.length + " new rows to MasterData.");
    }
    if (newAuthRows.length > 0) {
      if (authSheet.getLastRow() === 0) { authSheet.appendRow(['rollNo', 'Password', 'Timestamp']); }
      authSheet.getRange(authSheet.getLastRow() + 1, 1, newAuthRows.length, newAuthRows[0].length).setValues(newAuthRows);
      Logger.log("processStudentCsv: Added " + newAuthRows.length + " new rows to Authorisation.");
    }

    logAdminAction_("BULK UPLOAD", "Processed CSV: " + newCount + " new, " + updatedCount + " updated.", Session.getActiveUser().getEmail());
    return { success: true, message: "✅ Processed: " + newCount + " new students, " + updatedCount + " updated students." };
  } catch (e) {
    Logger.log("CSV Upload Failed: " + e.stack);
    return { success: false, message: "❌ Error processing CSV: " + e.message };
  }
}

function getStudentProfileConfig() {
  if (!checkAdminAccess("Viewer")) { 
    return { success: false, error: "Access Denied" }; 
  }
  
  try {
    var masterSheet = getSS().getSheetByName(MASTER_SHEET_NAME);
    if (!masterSheet || masterSheet.getLastRow() < 1) {
      return { success: false, error: "No master data sheet found" };
    }

    var header = masterSheet.getRange(1, 1, 1, masterSheet.getLastColumn()).getValues()[0];
    var config = [];
    
    var configSheet = ensureStudentProfileConfigSchema_();
    var savedConfig = {};
    
    if (configSheet.getLastRow() > 1) {
      var configData = configSheet.getRange(2, 1, configSheet.getLastRow() - 1, 2).getValues();
      for (var i = 0; i < configData.length; i++) {
        var fieldName = String(configData[i][0] || '').trim();
        var isEditable = configData[i][1] === true || configData[i][1] === "TRUE" || configData[i][1] === "true";
        if (fieldName) {
          savedConfig[fieldName] = isEditable;
        }
      }
    }
    
    for (var i = 0; i < header.length; i++) {
      var fieldName = String(header[i] || '').trim();
      if (fieldName) {
        var isEditable = savedConfig[fieldName] !== undefined ? savedConfig[fieldName] : isFieldEditableByDefault_(fieldName);
        config.push({
          name: fieldName,
          isEditable: isEditable
        });
      }
    }
    
    return { success: true, config: config };
  } catch (e) {
    Logger.log("Error in getStudentProfileConfig: " + e.stack);
    return { success: false, error: "Server error: " + e.message };
  }
}

function isFieldEditableByDefault_(fieldName) {
  var defaultEditableFields = ["Personal Email ID", "Mobile No"];
  return defaultEditableFields.indexOf(fieldName) !== -1;
}

function getEditableFields_() {
  try {
    var configSheet = ensureStudentProfileConfigSchema_();
    var editableFields = [];
    
    if (configSheet.getLastRow() > 1) {
      var configData = configSheet.getRange(2, 1, configSheet.getLastRow() - 1, 2).getValues();
      for (var i = 0; i < configData.length; i++) {
        var fieldName = String(configData[i][0] || '').trim();
        var isEditable = configData[i][1] === true || configData[i][1] === "TRUE" || configData[i][1] === "true";
        if (fieldName && isEditable) {
          editableFields.push(fieldName);
        }
      }
    }
    
    return editableFields.length > 0 ? editableFields : ["Personal Email ID", "Mobile No"];
  } catch (e) {
    Logger.log("Error in getEditableFields_: " + e.stack);
    return ["Personal Email ID", "Mobile No"];
  }
}

function setStudentProfileConfig(config) {
  if (!checkAdminAccess("Editor")) { 
    return { success: false, message: "Access Denied" }; 
  }
  
  try {
    if (!config || !Array.isArray(config)) {
      return { success: false, message: "Invalid configuration data provided" };
    }
    
    var sheet = ensureStudentProfileConfigSchema_();
    
    if (sheet.getLastRow() > 1) {
      sheet.deleteRows(2, sheet.getLastRow() - 1);
    }
    
    var dataRows = [];
    for (var i = 0; i < config.length; i++) {
      if (config[i] && config[i].name) {
        dataRows.push([
          config[i].name,
          config[i].isEditable || false
        ]);
      }
    }
    
    if (dataRows.length > 0) {
      sheet.getRange(2, 1, dataRows.length, 2).setValues(dataRows);
    }
    
    Logger.log("Student profile config updated to sheet with " + dataRows.length + " fields");
    logAdminAction_("PROFILE CONFIG", "Updated student profile field configuration", Session.getActiveUser().getEmail());
    
    return { success: true, message: "Profile configuration saved successfully" };
  } catch (e) {
    Logger.log("Error in setStudentProfileConfig: " + e.stack);
    return { success: false, message: "Server error: " + e.message };
  }
}
