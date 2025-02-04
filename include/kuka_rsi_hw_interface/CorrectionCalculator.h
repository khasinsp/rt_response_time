//
// Created by muellerm on 01.11.16.
//

#ifndef KUKA_RSI_HW_INTERFACE_CORRECTIONCALCULATOR_H
#define KUKA_RSI_HW_INTERFACE_CORRECTIONCALCULATOR_H

#include <kuka_rsi_hw_interface/KukaAxes.h>
#include <unordered_map>
#include <fstream>

// ROS
// #include <ros/ros.h>

#include <cmath>


#include <iostream>
#include <deque>
#include <array>
#include <numeric>

/*
void logMatrix(const std::vector<std::vector<double>>& matrix) {
    std::ostringstream oss;
    for (const auto& row : matrix) {
        oss << "[ ";
        for (const auto& elem : row) {
            oss << elem << " ";
        }
        oss << "]\n";
    }
    ROS_INFO_STREAM(oss.str());
}

// Function to multiply two matrices
std::vector<std::vector<double>> matmul(const std::vector<std::vector<double>>& A, const std::vector<std::vector<double>>& B) {
    int rowsA = A.size();
    int colsA = A[0].size();
    int rowsB = B.size();
    int colsB = B[0].size();

    if (colsA != rowsB) {
        std::cerr << "Matrix dimensions are incompatible for multiplication!" << std::endl;
        exit(EXIT_FAILURE);}
    std::vector<std::vector<double>> result(rowsA, std::vector<double>(colsB, 0));
    for (int i = 0; i < rowsA; i++) {
        for (int j = 0; j < colsB; j++) {
            for (int k = 0; k < colsA; k++) {
                result[i][j] += A[i][k] * B[k][j];}}}
    return result;
}

// Function to add two matrices
std::vector<std::vector<double>> matrixAddition(const std::vector<std::vector<double>>& A, const std::vector<std::vector<double>>& B) {
    int rowsA = A.size();
    int colsA = A[0].size();
    int rowsB = B.size();
    int colsB = B[0].size();

    if (rowsA != rowsB || colsA != colsB) {
        std::cerr << "Matrix dimensions must match for addition!" << std::endl;
        exit(EXIT_FAILURE);}
    std::vector<std::vector<double>> result(rowsA, std::vector<double>(colsA, 0));
    for (int i = 0; i < rowsA; i++) {
        for (int j = 0; j < colsA; j++) {
            result[i][j] = A[i][j] + B[i][j];}}

    return result;
}

// Function to perform matrix inversion with regularization
std::vector<std::vector<double>> invertMatrix(const std::vector<std::vector<double>>& A, double regularization_factor = 1e-6) {
    int n = A.size();
    
    // Check if the matrix is square
    if (n != A[0].size()) {
        throw std::invalid_argument("Matrix must be square for inversion!");
    }

    // Create a copy of A to modify and apply regularization
    std::vector<std::vector<double>> augmented(n, std::vector<double>(n * 2, 0));

    // Copy A into the left side of the augmented matrix
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            augmented[i][j] = A[i][j];}}

    // Add regularization by adding a scaled identity matrix to the original matrix
    for (int i = 0; i < n; i++) {
        augmented[i][i] += regularization_factor;}  // Apply regularization}

    // Create the identity matrix on the right side of the augmented matrix
    for (int i = 0; i < n; i++) {
        augmented[i][i + n] = 1;}

    // Perform Gaussian elimination with partial pivoting
    for (int i = 0; i < n; i++) {
        // Find the row with the largest pivot
        int max_row = i;
        for (int j = i + 1; j < n; j++) {
            if (std::abs(augmented[j][i]) > std::abs(augmented[max_row][i])) {
                max_row = j;}}

        // Swap rows if necessary
        if (max_row != i) {
            std::swap(augmented[i], augmented[max_row]);}

        // Make the pivot element equal to 1 by dividing the row by the pivot
        double pivot = augmented[i][i];
        for (int j = 0; j < 2 * n; j++) {
            augmented[i][j] /= pivot;}

        // Eliminate other rows
        for (int j = 0; j < n; j++) {
            if (j != i) {
                double factor = augmented[j][i];
                for (int k = 0; k < 2 * n; k++) {
                    augmented[j][k] -= factor * augmented[i][k];}}}}

    // Extract the inverted matrix from the augmented matrix
    std::vector<std::vector<double>> inverse(n, std::vector<double>(n, 0));
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            inverse[i][j] = augmented[i][j + n];}}

    return inverse;
}

// Function to transpose a matrix
std::vector<std::vector<double>> transpose(const std::vector<std::vector<double>>& A) {
    int rows = A.size();
    int cols = A[0].size();

    // Create a new matrix with flipped dimensions (rows become columns and columns become rows)
    std::vector<std::vector<double>> transposed(cols, std::vector<double>(rows));
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            transposed[j][i] = A[i][j];}}
    return transposed;
}

// Function to negate a matrix
std::vector<std::vector<double>> negate(const std::vector<std::vector<double>>& mat) {
    std::vector<std::vector<double>> result(mat.size(), std::vector<double>(mat[0].size()));
    for (size_t i = 0; i < mat.size(); i++) {
        for (size_t j = 0; j < mat[0].size(); j++) {
            result[i][j] = -mat[i][j];
        }
    }
    return result;
}



class KalmanFilter {
public:
    bool initialized; // Initialization flag
    KalmanFilter(double dt) : initialized(false) {
        F = std::vector<std::vector<double>>(18, std::vector<double>(18, 0));
        H = std::vector<std::vector<double>>(6, std::vector<double>(18, 0));
        P = std::vector<std::vector<double>>(18, std::vector<double>(18, 0));
        Q = std::vector<std::vector<double>>(18, std::vector<double>(18, 0));
        R = std::vector<std::vector<double>>(6, std::vector<double>(6, 0));
        x = std::vector<std::vector<double>>(18, std::vector<double>(1, 0));
        I = std::vector<std::vector<double>>(18, std::vector<double>(18, 0));

        for (int i = 0; i < 18; i++) I[i][i] = 1;

        // Initialize state transition matrix F with position-velocity-acceleration relationships
        for (int i = 0; i < 6; i++) {
            F[i][i] = 1.0;
            F[i][i + 6] = dt;
            F[i][i + 12] = 0.5 * dt * dt;
            F[i + 6][i + 6] = 1.0;
            F[i + 6][i + 12] = dt;
            F[i + 12][i + 12] = 1.0;
        }

        // Initialize process noise covariance matrix Q with small values for velocity and acceleration noise
        double position_noise = 1e-5;
        double velocity_noise = 1e-4;
        double acceleration_noise = 1e-3;
        for (int i = 0; i < 6; i++) {
            Q[i][i] = position_noise;
            Q[i + 6][i + 6] = velocity_noise;
            Q[i + 12][i + 12] = acceleration_noise;
        }

        // Initialize measurement matrix H to map state vector x to position measurements
        for (int i = 0; i < 6; i++) {
            H[i][i] = 1.0;  // Position measurement only, so H maps position states to measurement space
        }

        // Initialize measurement noise covariance matrix R with reasonable measurement noise values
        double measurement_noise = 1e-4;
        for (int i = 0; i < 6; i++) {
            R[i][i] = measurement_noise;
        }

        // Initialize state covariance matrix P with larger values, indicating initial uncertainty
        double initial_position_uncertainty = 1e-5;//1.0;
        double initial_velocity_uncertainty = 1e-5;//1.0;
        double initial_acceleration_uncertainty = 1e-5;//1.0;
        for (int i = 0; i < 6; i++) {
            P[i][i] = initial_position_uncertainty;
            P[i + 6][i + 6] = initial_velocity_uncertainty;
            P[i + 12][i + 12] = initial_acceleration_uncertainty;
        }
    }

    void predict() {
        //ROS_INFO_STREAM("PREDICT");
        x = matmul(F, x);
        //ROS_INFO_STREAM("x: ");
        //logMatrix(x);
        P = matmul(matmul(F, P), transpose(F));
        P = matrixAddition(P, Q);
    }

    void update(const std::vector<std::vector<double>>& z) {
        //ROS_INFO_STREAM("UPDATE");
        std::vector<std::vector<double>> y = matrixAddition(z, negate(matmul(H, x)));
        std::vector<std::vector<double>> S = matrixAddition(matmul(H, matmul(P, transpose(H))), R);
        std::vector<std::vector<double>> K = matmul(P, transpose(H));
        K = matmul(K, invertMatrix(S));
        x = matrixAddition(x, matmul(K, y));
        P = matmul(matrixAddition(I, negate(matmul(K, H))), P);
        //ROS_INFO_STREAM("x: ");
        //logMatrix(x);

    }

    std::vector<double> filter(const std::vector<double>& position_measurement) {

        if (!initialized) {
            // Use first measurement to initialize the state vector
            for (int i = 0; i < 6; i++) {
                x[i][0] = position_measurement[i]; // Initialize position
                x[i + 6][0] = 0.0;                 // Set initial velocity to zero
                x[i + 12][0] = 0.0;                // Set initial acceleration to zero
            }
            
            // Set up initial covariance with small values for position and larger for velocity and acceleration
            for (int i = 0; i < 6; i++) {
                P[i][i] = 1e-2;     // Small variance for initial position states
                P[i + 6][i + 6] = 1e1; // Larger variance for initial velocity states
                P[i + 12][i + 12] = 1e1; // Larger variance for initial acceleration states
            }


            ROS_INFO_STREAM("INITIALIZED");
            ROS_INFO_STREAM("x: ");
            logMatrix(x);

            initialized = true; // Mark as initialized
            return position_measurement; // Return the initial position measurement as the estimate
        }


        // Convert position measurement to column vector form
        std::vector<std::vector<double>> z(6, std::vector<double>(1));
        for (int i = 0; i < 6; i++) z[i][0] = position_measurement[i];

        // Prediction step
        predict();

        // Update step with the measurement
        update(z);

        // Extract the position estimate from the state vector x
        std::vector<double> position_estimate(6);
        for (int i = 0; i < 6; i++) position_estimate[i] = x[i][0];

        return position_estimate;
    }

private:
    std::vector<std::vector<double>> F, H, P, Q, R, x, I;
};

*/

template<class T, class U, class R>
class BiFunction {
public:
    virtual R apply(const T &t, const U &u, bool NoCorrection ) = 0;
};

namespace kuka_rsi_hw_interface {

    class CorrectionCalculator : public BiFunction<KukaAxes, KukaAxes, KukaAxes> {
    public:

        bool exceededDifference = false;
        /// Calculate the correction to reacht target_value with help of the current_value
        /// \param target_value the desired joint values
        /// \param current_value the current joint value
        /// \return a correction for all joints
        virtual KukaAxes apply(const KukaAxes &target_value, const KukaAxes &current_value, bool NoCorrection) = 0;

        /// Initialize this calculator
        /// \param current_value the initial value of the position of all joints at start-time
        virtual void init(const KukaAxes &current_value) {}
    };


    ///
    /// Calculate a correction by taking the difference between target_value and current_value
    ///
    class DifferentialCorrectionCalculator : public CorrectionCalculator {
    public:
           // Constructor with no parameters
        DifferentialCorrectionCalculator() : enableLogging(false) {}

        // Constructor with logging parameters
        DifferentialCorrectionCalculator(bool logging, const std::string &logFolderPath)
            : enableLogging(logging) {
            if (enableLogging) {
            // logFileName = generateLogFileName(logFolderPath);
            outFile = MakeCsvFileWithHeader(logFolderPath);
            }
        }

        // Constructor with parameter file and optional logging parameters
        DifferentialCorrectionCalculator(const std::string &filename, bool logging = false, const std::string &logFolderPath  = "")
            : enableLogging(logging) {
            if (!filename.empty()) {
                loadParameters(filename);
            } 
            if (enableLogging) {
            // logFileName = generateLogFileName(logFolderPath);
            outFile = MakeCsvFileWithHeader(logFolderPath);
            }
        }

            virtual KukaAxes apply(const KukaAxes &target_value, const KukaAxes &current_value, bool NoCorrection) {
                KukaAxes axes = KukaAxes();

                auto t0_corr = std::chrono::high_resolution_clock::now();

                if (exceededDifference or NoCorrection) {
                    // Return zero correction for all axes if the difference from target value is too high
                    for (int i = 0; i < KukaAxes::MAX_INTERNAL_AXES; ++i) {
                        axes.getInternalAxes()[i] = 0;
                    }
                    for (int i = 0; i < KukaAxes::MAX_EXTERNAL_AXES; ++i) {
                        axes.getExternalAxes()[i] = 0;
                    }
                } else {
                    // ROS_INFO_STREAM("diff A6 " << "  " <<  target_value.getInternalAxes()[5] - current_value.getInternalAxes()[5]);
                    // ROS_INFO_STREAM("diff A1 -> " << " ist " <<  current_value.getInternalAxes()[0] << " soll : " << target_value.getInternalAxes()[0]);
                    // float max_diff = 0.0;
                    for (int i = 0; i < KukaAxes::MAX_INTERNAL_AXES; ++i) {

                        
                            double error = target_value.getInternalAxes()[i] - current_value.getInternalAxes()[i];
                            integralError[i] += error; // Accumulate error for integral action
                            integralError[i] *= 0.90; // decay

                            PCorrection[i] = Kp[i] * error;
                            ICorrection[i] = Ki[i] * integralError[i];

                            axes.getInternalAxes()[i] = capCorrection(
                                Kp[i] * error + Ki[i] * integralError[i],
                                maxCorrection[i]
                            );

                        //if (std::abs(target_value.getInternalAxes()[i] - current_value.getInternalAxes()[i]) > max_diff){
                        //    max_diff = std::abs(target_value.getInternalAxes()[i] - current_value.getInternalAxes()[i]);
                        //}
    
                        if (std::abs(target_value.getInternalAxes()[i] - current_value.getInternalAxes()[i]) > 10) {
                            exceededDifference = true;
                            // ROS_INFO_STREAM("exceeded allowed tracking error. max = " << 10 << " - current = " << (std::abs(target_value.getInternalAxes()[i] - current_value.getInternalAxes()[i])));
                            // ROS_INFO_STREAM("setting exceededDifference = true");
                            //ros::shutdown();
                            }
                        }

                    // ROS_INFO_STREAM("max_diff target vs current = " << max_diff);

                    for (int i = 0; i < KukaAxes::MAX_EXTERNAL_AXES; ++i) {
                        axes.getExternalAxes()[i] = target_value.getExternalAxes()[i] - current_value.getExternalAxes()[i];
                    }
                }


                // auto t1_corr = std::chrono::high_resolution_clock::now();
                capDifference(axes); // Cap the difference between previous and current correction
                // ROS_INFO_STREAM("correction A6 post cap " << axes.getInternalAxes()[5]);

                // auto t2_corr = std::chrono::high_resolution_clock::now();
                if (enableLogging) {
                    // ROS_INFO_STREAM("logging axes");
                    // logCorrectionsAndDifferences(axes);
                    appendDataToCsv(current_value.getInternalAxes(), target_value.getInternalAxes(), axes.getInternalAxes(), PCorrection, ICorrection);
                }

                /*
                auto t3_corr = std::chrono::high_resolution_clock::now();             
                auto time_total = std::chrono::duration<float, std::micro>(t3_corr - t0_corr).count()*0.001;
                auto time_calc = std::chrono::duration<float, std::micro>(t1_corr - t0_corr).count()*0.001;
                auto time_cap = std::chrono::duration<float, std::micro>(t2_corr - t1_corr).count()*0.001;
                auto time_save = std::chrono::duration<float, std::micro>(t3_corr - t2_corr).count()*0.001;

                if (time_total > 8){
                    ROS_INFO_STREAM(" -- correction calculation function took too long : " << time_total);
                    ROS_INFO_STREAM(" -- -- time cal : " << time_calc);
                    ROS_INFO_STREAM(" -- -- time cao : " << time_cap);
                    ROS_INFO_STREAM(" -- -- time save : " << time_save);
                }
                */

                previousCorrection = axes;
                return axes;
            
    }
        private:
            std::string generateLogFileName(const std::string &folderPath) {
                std::ostringstream ss;
                auto t = std::time(nullptr);
                auto tm = *std::localtime(&t);

                ss << folderPath << "/log_";
                ss << std::put_time(&tm, "%Y-%m-%d_%H-%M-%S");
                ss << ".txt";

                return ss.str();
            }

            std::ofstream MakeCsvFileWithHeader(const std::string &folderPath) {
                auto now = std::chrono::system_clock::now();
                auto now_t = std::chrono::system_clock::to_time_t(now);
                auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count() % 1000000;

                std::tm tm = *std::localtime(&now_t);
                std::ostringstream ss;
                ss << folderPath << "/controller_log_";
                ss << std::put_time(&tm, "%Y-%m-%d_%H-%M-%S") << "."
                << std::setw(6) << std::setfill('0') << microseconds;  // Add microseconds
                ss << ".csv";  // Use .csv extension
                std::string filePath = ss.str();

                // Open the file and write the header
                std::ofstream outFile(filePath);
                if (outFile.is_open()) {
                    outFile << "Timestamp,"
                            << "Current_Joint1,Current_Joint2,Current_Joint3,Current_Joint4,Current_Joint5,Current_Joint6,"
                            //<< "FilteredCurrent_Joint1,FilteredCurrent_Joint2,FilteredCurrent_Joint3,FilteredCurrent_Joint4,FilteredCurrent_Joint5,FilteredCurrent_Joint6,"
                            << "Target_Joint1,Target_Joint2,Target_Joint3,Target_Joint4,Target_Joint5,Target_Joint6,"
                            << "Correction_Joint1,Correction_Joint2,Correction_Joint3,Correction_Joint4,Correction_Joint5,Correction_Joint6,"
                            << "P_Term_Joint1,P_Term_Joint2,P_Term_Joint3,P_Term_Joint4,P_Term_Joint5,P_Term_Joint6,"
                            << "I_Term_Joint1,I_Term_Joint2,I_Term_Joint3,I_Term_Joint4,I_Term_Joint5,I_Term_Joint6\n";
                    //outFile.close();
                    std::cout << "CSV file created with header at: " << filePath << "\n";
                } else {
                    std::cerr << "Error opening file for writing.\n";
                }

                return outFile;
            }

            
            void loadParameters(const std::string &filename) {
                std::ifstream file(filename);
                if (!file.is_open()) {
                    std::cerr << "Unable to open file: " << filename << std::endl;
                    return;
                }

                std::string line;
                std::unordered_map<std::string, int> jointMap = {
                    {"joint1", 0}, {"joint2", 1}, {"joint3", 2}, {"joint4", 3}, {"joint5", 4}, {"joint6", 5}
                };

                std::vector<double> accelerationLimits(KukaAxes::MAX_INTERNAL_AXES);
                std::vector<double> velocityLimits(KukaAxes::MAX_INTERNAL_AXES);

                while (std::getline(file, line)) {
                    if (line.find("betty_kuka_kr30_config.joint_acceleration_limits") != std::string::npos) {
                        std::size_t start = line.find('[') + 1;
                        std::size_t end = line.find(']');
                        std::string values = line.substr(start, end - start);
                        std::istringstream ss(values);
                        std::string token;
                        int index = 0;
                        while (std::getline(ss, token, ',') && index < KukaAxes::MAX_INTERNAL_AXES) {
                            accelerationLimits[index++] = std::stod(token);
                            // ROS_INFO_STREAM("acc limit loaded: " << accelerationLimits[index]);
                        }
                    }
                    else if (line.find("betty_kuka_kr30_config.joint_velocity_limits") != std::string::npos) {
                        std::size_t start = line.find('[') + 1;
                        std::size_t end = line.find(']');
                        std::string values = line.substr(start, end - start);
                        std::istringstream ss(values);
                        std::string token;
                        int index = 0;
                        while (std::getline(ss, token, ',') && index < KukaAxes::MAX_INTERNAL_AXES) {
                            velocityLimits[index++] = std::stod(token);
                            // ROS_INFO_STREAM("vel limit loaded: " << velocityLimits[index]);
                        }
                    }
                }

                file.close();

                for (int i = 0; i < KukaAxes::MAX_INTERNAL_AXES; ++i) {
                    // trying to get better limits
                    // maxDifference[i] = accelerationLimits[i]*180/M_PI/6400*4;
                    // maxCorrection[i] = velocityLimits[i]*180/M_PI/80*2.1;
                    maxDifference[i] = accelerationLimits[i]*180/M_PI/640*1.1;
                    maxCorrection[i] = velocityLimits[i]*180/M_PI/80*1.1;
                    
                }
            }
            
            double capCorrection(double correction, double maxCorrection) {
            
                return std::max(-maxCorrection, std::min(correction, maxCorrection));
            }

            void capDifference(KukaAxes &axes) {
                for (int i = 0; i < KukaAxes::MAX_INTERNAL_AXES; ++i) {
                    double diff = axes.getInternalAxes()[i] - previousCorrection.getInternalAxes()[i];
                    if (std::abs(diff) > maxDifference[i]) {
                        axes.getInternalAxes()[i] = previousCorrection.getInternalAxes()[i] + maxDifference[i] * (diff > 0 ? 1 : -1);
                    }
                    //if (std::abs(diff) > 0.3) {
                    //    axes.getInternalAxes()[i] = previousCorrection.getInternalAxes()[i] + 0.3 * (diff > 0 ? 1 : -1);
                    //}
                }
                //ROS_INFO_STREAM("test " <<  axes.getInternalAxes()[0] << "  " << axes.getInternalAxes()[1] << " " << axes.getInternalAxes()[2] );
                               
            }

            /*
            void logCorrectionsAndDifferences(const KukaAxes &axes) {
                std::ofstream logFile(logFileName, std::ios_base::app);
                if (!logFile.is_open()) {
                    std::cerr << "Unable to open log file: " << logFileName << std::endl;
                    return;
                }

                logFile << "Corrections: ";
                for (int i = 0; i < KukaAxes::MAX_INTERNAL_AXES; ++i) {
                    logFile << axes.getInternalAxes()[i] << " ";
                }

                logFile << "\nDifferences: ";
                for (int i = 0; i < KukaAxes::MAX_INTERNAL_AXES; ++i) {
                    double diff = axes.getInternalAxes()[i] - previousCorrection.getInternalAxes()[i];
                    logFile << diff << " ";
                }
                logFile << "\n";

                logFile.close();
            }
            */

            // Function to append a data row to the CSV file
            void appendDataToCsv(const std::vector<double>& currentValues,
                                //const std::vector<double>& filteredValues,
                                const std::vector<double>& targetValues,
                                const std::vector<double>& corrections,
                                const double PCorrection[6], 
                                const double ICorrection[6]) {

                // std::ofstream outFile(logFileName, std::ios_base::app);
                if (outFile.is_open()) {
                    auto now = std::chrono::system_clock::now();
                    auto epoch = now.time_since_epoch();
                    
                    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(epoch);
                    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(epoch - seconds);
                    
                    std::time_t tt = std::chrono::system_clock::to_time_t(now);
                    outFile << std::put_time(std::localtime(&tt), "%Y-%m-%d %H-%M-%S") << "." 
                            << std::setw(6) << std::setfill('0') << microseconds.count();
                    
                    // Write data for each category
                    for (const auto& val : currentValues) outFile << "," << val;
                    //for (const auto& val : filteredValues) outFile << "," << val;
                    for (const auto& val : targetValues) outFile << "," << val;
                    for (const auto& val : corrections) outFile << "," << val;        
                    // Write the P and I terms (stored in PCorrection and ICorrection)
                    for (int i = 0; i < 6; ++i) {
                        outFile << "," << PCorrection[i]; // Proportional corrections
                    }
                    for (int i = 0; i < 6; ++i) {
                        outFile << "," << ICorrection[i]; // Integral corrections
                    }

                    outFile << "\n";
                } else {
                    std::cerr << "Error opening file for appending.\n";
                }
            }

            bool enableLogging;
            std::ofstream outFile;
            double maxDifference[KukaAxes::MAX_INTERNAL_AXES] = {10e6, 10e6, 10e6, 10e6, 10e6, 10e6}; // Default Max difference for external axes
            double maxCorrection[KukaAxes::MAX_INTERNAL_AXES] = {10e6, 10e6, 10e6, 10e6, 10e6, 10e6}; // Default Max correction for external axes
            KukaAxes previousCorrection; // Previous correction values
            double Kp[KukaAxes::MAX_INTERNAL_AXES] = {0.5, 0.5, 0.5, 0.5, 0.5, 0.5}; // Proportional gains for each joint
            double Ki[KukaAxes::MAX_INTERNAL_AXES] = { 0.01,  0.01,  0.01,  0.01, 0.01, 0.01}; // Integral gains for each joint
            //double Ki[KukaAxes::MAX_INTERNAL_AXES] = { 0.01,  0.00,  0.01,  0.01, 0.01, 0.01}; // Integral gains for each joint
            //double Kp[KukaAxes::MAX_INTERNAL_AXES] = {0.3, 0.3, 0.3, 0.3, 0.3, 0.3}; // Proportional gains for each joint
            double integralError[KukaAxes::MAX_INTERNAL_AXES] = {0.0, 0.0, 0.0, 0.0, 0.0, 0.0}; // Integral error for each joint

            double PCorrection[6] = {0.0, 0.0, 0.0, 0.0, 0.0, 0.0};
            double ICorrection[6] = {0.0, 0.0, 0.0, 0.0, 0.0, 0.0};

            // KalmanFilter kalman_filter;
            // std::vector<double> filtered_value;

        };



    ///
    /// Use the initial position as a reference to calculate the correction. This is used when the KRC is in Absolute mode
    /// NB: we we're unable to set the KRC2 into absolute mode
    ///
    class InitialPositionCorrectionCalculator : public CorrectionCalculator {
    public:

        InitialPositionCorrectionCalculator() : calculator_() {

        }

        virtual void init(const KukaAxes &current_value) {
            initialPosition_ = current_value;
        }

        virtual KukaAxes apply(const KukaAxes &target_value, const KukaAxes &, bool NoCorrection = false) {
            return calculator_.apply(target_value, initialPosition_, false);
        }

    private:
        KukaAxes initialPosition_;
        DifferentialCorrectionCalculator calculator_;
    };

    ///
    /// Remembers last correction and adds it to the new current_value to get an estimation of the actual current_value
    /// The latency of the Robot-Controller seems to be about one cycle
    /// This seems to prevent oscillation caused by overcontrolling the setpoint values.
    ///
    class EstimationDecorator : public CorrectionCalculator {
    public:
        EstimationDecorator(std::shared_ptr<CorrectionCalculator> calculator)
                : calculator_(calculator), lastCorrection_() /* initialize with all zeros */ {}

        virtual KukaAxes apply(const KukaAxes &target_value, const KukaAxes &current_value, bool NoCorrection = false) {
            // setpoint position received over RSI is 1 cycle older as expected, therefore we add the last correction
            const KukaAxes &est_current_value = current_value.add(lastCorrection_);
            lastCorrection_ = calculator_->apply(target_value, est_current_value,NoCorrection);
            return lastCorrection_;
        }

    private:
        KukaAxes lastCorrection_;
        std::shared_ptr<CorrectionCalculator> calculator_;
    };

    ///
    /// only use the target_value and the previous target_value to calculate a correction
    /// NB: does not work very well
    ///
    class CommandOnlyCalculator : public CorrectionCalculator {
    public:
        CommandOnlyCalculator() : calculator_() { }

        virtual KukaAxes apply(const KukaAxes &target_value, const KukaAxes &, bool NoCorrection = false) {
            KukaAxes corr = calculator_.apply(target_value, lastTargetValue_,false);
            lastTargetValue_ = target_value;
            return corr;
        }

        virtual void init(const KukaAxes &current_value) {
            lastTargetValue_ = current_value;
        }

    private:
        KukaAxes lastTargetValue_;
        DifferentialCorrectionCalculator calculator_;
    };


    ///
    /// Decorator which prevents calculation of a correction (i.e. non-zero-correction) if the previous target value
    /// has not been reached by the controller yet.
    /// NB: does not work well...
    ///
    class WaitForTargetDecorator : public CorrectionCalculator {
    public:
        WaitForTargetDecorator(std::shared_ptr<CorrectionCalculator> calculator)
                : calculator_(calculator) {}

        virtual KukaAxes apply(const KukaAxes &target_value, const KukaAxes &current_value, bool NoCorrection = false) {
            if (lastTarget_ && !isEqual(current_value, *lastTarget_)) {
                // target not yet reached...
                return KukaAxes();
            }
            // target reached -> remember new target
            lastTarget_ = std::make_shared<KukaAxes>(target_value);
            return calculator_->apply(target_value, current_value,0);
        }

    private:
        bool isEqual(const KukaAxes &first, const KukaAxes &second) {
            return isInTolerance(first.getInternalAxes(), second.getInternalAxes(), TOLERANCE_INTERNAL) &&
                   isInTolerance(first.getExternalAxes(), second.getExternalAxes(), TOLERANCE_EXTERNAL);
        }

        bool
        isInTolerance(const std::vector<double> &first, const std::vector<double> &second, const double &tolerance) {
            assert(first.size() == second.size());
            for (int i = 0; i < first.size(); ++i) {
                if (!isInTolerance(first[i], second[i], tolerance)) {
                    return false;
                }
            }
            return true;
        }

        bool isInTolerance(const double &first, const double &second, const double &tolerance) {
            return fabs(first - second) <= tolerance;
        }

    private:
        static const double TOLERANCE_INTERNAL;
        static const double TOLERANCE_EXTERNAL;
        std::shared_ptr<CorrectionCalculator> calculator_;

        std::shared_ptr<KukaAxes> lastTarget_;

    };

    const double WaitForTargetDecorator::TOLERANCE_INTERNAL = 1e-1;
    const double WaitForTargetDecorator::TOLERANCE_EXTERNAL = 1;
}
#endif //KUKA_RSI_HW_INTERFACE_CORRECTIONCALCULATOR_H
