

#ifndef NONCOPYABLE_HPP

#define NONCOPYABLE_HPP



class NonCopyable {
protected:


	NonCopyable() = default;
	~NonCopyable() = default;

	//copying prohibited
	NonCopyable(const NonCopyable&) = delete;
	NonCopyable& operator=(const NonCopyable&) = delete;

	//moving prohibited
	NonCopyable(NonCopyable&&) = delete;
	NonCopyable& operator=(NonCopyable&&) = delete;
};





#endif //NONCOPYABLE_HPP