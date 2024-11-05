package nextstep.app.domain.member.service;

import nextstep.app.domain.member.param.Member;
import nextstep.app.domain.member.repository.MemberRepository;
import nextstep.security.service.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MemberService implements UserDetailsService {

    private final MemberRepository memberRepository;

    public MemberService(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    @Override
    public Member retrieveUserDetailsByEmailAndPassword(String email, String password) {
        return memberRepository.findByEmail(email)
                .filter(member -> member.getPassword().equals(password))
                .orElse(null);
    }

    public List<Member> retrieveMembers() {
        return memberRepository.findAll();
    }
}
