using System.Text.Json.Serialization;

namespace KalkanCore.DTO;


[Flags]
public enum ApiResultEnum{
    Success = 1,
    ErrorValidation = 2,
    ErrorLogic = 3,
    ErrorGlobal = 4
}

public class ApiResult<T>
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public ApiResultEnum Success { get; set; }
    public object ErrorMessage { get; set; }

    public T? Data { get; set; }

    public ApiResult() {
        
    }
    
    public static ApiResult<T> GetSuccess(T data) {
        return new ApiResult<T> { Success = ApiResultEnum.Success, Data = data };
    }

    public static ApiResult<T> GetError(Exception ex = null, T data = default, bool logError = true) {
        return new ApiResult<T> { Success = ApiResultEnum.ErrorLogic, ErrorMessage = ex?.ToString()!, Data = data };
    }
    
    public static ApiResult<T> GetError(string ex = null, T data = default, bool logError = true) {
        return new ApiResult<T> { Success = ApiResultEnum.ErrorLogic, ErrorMessage = ex, Data = data };
    }
    
    public static ApiResult<T> GetErrorValidation(object ex, T data = default, bool logError = false) {
        return new ApiResult<T> { Success = ApiResultEnum.ErrorValidation, ErrorMessage = ex, Data = data };
    }
    
    public static ApiResult<T> GetErrorLogic(object ex, T data = default, bool logError = false) {
        return new ApiResult<T> { Success = ApiResultEnum.ErrorLogic, ErrorMessage = ex?.ToString()!, Data = data };
    }
    public static ApiResult<T> GetErrorLogic(T data = default, bool logError = false) {
        return new ApiResult<T> { Success = ApiResultEnum.ErrorLogic, Data = data };
    }
    
    public static ApiResult<T> GetErrorGlobal(object ex, T data = default, bool logError = true) {
        return new ApiResult<T> { Success = ApiResultEnum.ErrorGlobal, ErrorMessage = ex?.ToString()!, Data = data };
    }
}

public class ApiResult
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public ApiResultEnum Success { get; set; }

    public string ErrorMessage { get; set; }
    
    public object Data { get; set; }

    public ApiResult() {
        
    }

    public static ApiResult Failure(string errorMessage)
    {
        return new ApiResult{ Success = ApiResultEnum.ErrorLogic, ErrorMessage = errorMessage};
    }
    
    public static ApiResult GetSuccess() { return new ApiResult { Success = ApiResultEnum.Success }; }

    public static ApiResult GetError(Exception ex = null, bool logError = true) {
        return new ApiResult {
            Success = ApiResultEnum.ErrorLogic,
            ErrorMessage = ex?.ToString()!
            
        };
    }
    
    public static ApiResult GetError(string ex = null, bool logError = true) {
        return new ApiResult {
            Success = ApiResultEnum.ErrorLogic,
            ErrorMessage = ex
        };
    }

 public static ApiResult GetErrorValidation(object ex, bool logError = true) {
        return new ApiResult { Success = ApiResultEnum.ErrorValidation, ErrorMessage = ex?.ToString()!, Data = null };
    }
    
    public static ApiResult GetErrorLogic(object ex, bool logError = true) {
        return new ApiResult { Success = ApiResultEnum.ErrorLogic, ErrorMessage = ex?.ToString()!, Data = null };
    }
    
    public static ApiResult GetErrorGlobal(object ex, bool logError = true) {
        return new ApiResult { Success = ApiResultEnum.ErrorGlobal, ErrorMessage = ex?.ToString()!, Data = null };
    }
}