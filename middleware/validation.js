import AppError from "../helper/AppError.js";

const validate = (schema, property = "body") => {
    return (req,res,next) => {
        try{
            const parsed = schema.parsed(req[property]);
            req[property] = parsed;
            next();
        } catch(err){
            const message = err.errors?.[0]?.message || "Invalid request data";
            next(new AppError(message,400));
        }
    };
};

export default validate;